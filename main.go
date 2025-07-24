package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
	"google.golang.org/api/youtubeanalytics/v2"
	"google.golang.org/api/youtubereporting/v1"
	_ "modernc.org/sqlite"
)

// Config holds application configuration from environment variables
type Config struct {
	YouTubeAPIKey      string
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURL        string
	DatabasePath       string
}

// App holds the application's dependencies
type App struct {
	db           *sql.DB
	conf         *Config
	oauth2Config *oauth2.Config
	templates    *template.Template
}

// Token represents an OAuth token stored in the database
type Token struct {
	ID           int
	UserID       string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	TokenType    string
}

// TemplateData struct to pass data to the HTML template
type TemplateData struct {
	UserID string
}

// NewConfig creates a new Config struct from environment variables
func NewConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, assuming environment variables are set.")
	}

	conf := &Config{
		YouTubeAPIKey:      os.Getenv("YOUTUBE_API_KEY"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:        os.Getenv("REDIRECT_URL"),
		DatabasePath:       os.Getenv("DATABASE_PATH"),
	}

	if conf.YouTubeAPIKey == "" {
		return nil, fmt.Errorf("YOUTUBE_API_KEY not set in environment variables")
	}
	if conf.GoogleClientID == "" || conf.GoogleClientSecret == "" || conf.RedirectURL == "" {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or REDIRECT_URL not set for OAuth")
	}
	if conf.DatabasePath == "" {
		conf.DatabasePath = "./youtube_app.db" // Default database path
	}

	return conf, nil
}

// NewApp initializes a new App
func NewApp() (*App, error) {
	conf, err := NewConfig()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", conf.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %v", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL UNIQUE,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		expiry DATETIME NOT NULL,
		token_type TEXT NOT NULL
	);`
	if _, err := db.Exec(createTableSQL); err != nil {
		return nil, fmt.Errorf("error creating tokens table: %v", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     conf.GoogleClientID,
		ClientSecret: conf.GoogleClientSecret,
		RedirectURL:  conf.RedirectURL,
		Scopes: []string{
			youtubeanalytics.YtAnalyticsReadonlyScope,
			"https://www.googleapis.com/auth/yt-analytics.readonly",
			youtube.YoutubeReadonlyScope,
		},
		Endpoint: google.Endpoint,
	}

	templates, err := template.ParseFiles("index.html", "search_results.html", "analytics_table.html")
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %v", err)
	}

	log.Printf("Database initialized at %s", conf.DatabasePath)

	return &App{
		db:           db,
		conf:         conf,
		oauth2Config: oauth2Config,
		templates:    templates,
	}, nil
}

func main() {
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer app.db.Close()

	http.HandleFunc("/", app.serveIndex)
	http.HandleFunc("/search", app.handleYouTubeSearch)
	http.HandleFunc("/auth/google/login", app.handleGoogleLogin)
	http.HandleFunc("/auth/google/callback", app.handleGoogleCallback)
	http.Handle("/business", app.authMiddleware(http.HandlerFunc(app.handleBusinessAnalytics)))
	http.Handle("/creator", app.authMiddleware(http.HandlerFunc(app.handleCreatorAnalytics)))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (a *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := getUserIDFromCookie(r)
		if err != nil {
			log.Printf("authMiddleware: Authentication failed (cookie missing): %v", err)
			http.Error(w, "Authentication required. Please log in.", http.StatusUnauthorized)
			return
		}

		client, err := a.getAuthenticatedClient(userID)
		if err != nil {
			log.Printf("authMiddleware: Authentication failed: %v", err)
			http.Error(w, fmt.Sprintf("Authentication required: %v. Please log in.", err), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		ctx = context.WithValue(ctx, "authenticated_client", client)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	userID := ""
	cookie, err := r.Cookie("user_channel_id")
	if err == nil {
		userID = cookie.Value
		log.Printf("ServeIndex: UserID '%s' found in cookie.", userID)
	} else {
		log.Printf("ServeIndex: No user_channel_id cookie found: %v. User might need to authenticate.", err)
	}

	data := TemplateData{
		UserID: userID,
	}

	err = a.templates.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

func (a *App) handleYouTubeSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	service, err := youtube.NewService(ctx, option.WithAPIKey(a.conf.YouTubeAPIKey))
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating YouTube service: %v", err), http.StatusInternalServerError)
		return
	}

	call := service.Search.List([]string{"id", "snippet"}).
		Q(query).
		MaxResults(10).
		Type("video")

	response, err := call.Do()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error searching YouTube: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	err = a.templates.ExecuteTemplate(w, "search_results.html", response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

func (a *App) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := "random-state-string"
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   600, // 10 minutes
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	url := a.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	log.Printf("Redirecting to Google for OAuth: %s", url)
	w.Header().Set("HX-Redirect", url)
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("handleGoogleCallback: Received callback from Google OAuth.")

	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		log.Printf("handleGoogleCallback: missing oauthstate cookie: %v", err)
		http.Error(w, "Invalid state: missing cookie", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "oauthstate", MaxAge: -1, Path: "/"})

	if r.FormValue("state") != oauthState.Value {
		log.Printf("handleGoogleCallback: Invalid state parameter received: %s, expected %s", r.FormValue("state"), oauthState.Value)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	log.Println("handleGoogleCallback: State parameter validated.")

	code := r.FormValue("code")
	if code == "" {
		log.Println("handleGoogleCallback: Authorization code not found in callback.")
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}
	log.Println("handleGoogleCallback: Authorization code received.")

	token, err := a.oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("handleGoogleCallback: Error exchanging code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	log.Println("handleGoogleCallback: Token exchange successful.")

	oauthClient := a.oauth2Config.Client(context.Background(), token)
	youtubeService, err := youtube.NewService(context.Background(), option.WithHTTPClient(oauthClient))
	if err != nil {
		log.Printf("handleGoogleCallback: Error creating YouTube service: %v", err)
		http.Error(w, "Failed to create YouTube service", http.StatusInternalServerError)
		return
	}
	log.Println("handleGoogleCallback: YouTube service created for channel ID retrieval.")

	channelsCall := youtubeService.Channels.List([]string{"id"}).Mine(true)
	channelsResp, err := channelsCall.Do()
	if err != nil {
		log.Printf("handleGoogleCallback: Error fetching user's channel ID: %v", err)
		http.Error(w, "Failed to fetch user's channel ID", http.StatusInternalServerError)
		return
	}
	log.Println("handleGoogleCallback: Channel list call executed.")

	var authenticatedUserID string
	if len(channelsResp.Items) > 0 {
		authenticatedUserID = channelsResp.Items[0].Id
		log.Printf("handleGoogleCallback: Successfully fetched authenticated user's YouTube Channel ID: %s", authenticatedUserID)
	} else {
		log.Println("handleGoogleCallback: No YouTube channel found for the authenticated user.")
		http.Error(w, "No YouTube channel found for the authenticated user.", http.StatusBadRequest)
		return
	}

	err = a.saveToken(authenticatedUserID, token)
	if err != nil {
		log.Printf("handleGoogleCallback: Error saving token: %v", err)
		http.Error(w, fmt.Sprintf("Error saving token: %v", err), http.StatusInternalServerError)
		return
	}
	log.Println("handleGoogleCallback: Token saved to database.")

	http.SetCookie(w, &http.Cookie{
		Name:     "user_channel_id",
		Value:    authenticatedUserID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour * 30),
	})
	log.Printf("handleGoogleCallback: Set user_channel_id cookie for user: %s", authenticatedUserID)

	http.Redirect(w, r, "/", http.StatusFound)
	log.Println("handleGoogleCallback: Redirecting to /.")
}

func (a *App) getToken(userID string) (*oauth2.Token, error) {
	row := a.db.QueryRow("SELECT access_token, refresh_token, expiry, token_type FROM tokens WHERE user_id = ?", userID)
	var accessToken, refreshToken, tokenType string
	var expiry time.Time
	err := row.Scan(&accessToken, &refreshToken, &expiry, &tokenType)
	if err == sql.ErrNoRows {
		log.Printf("getToken: No token found in DB for user %s", userID)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getToken: error scanning token from DB: %v", err)
	}

	log.Printf("getToken: Retrieved token from DB for user %s. Expiry: %s, RefreshToken present: %t", userID, expiry.String(), refreshToken != "")
	return &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       expiry,
		TokenType:    tokenType,
	}, nil
}

func (a *App) saveToken(userID string, token *oauth2.Token) error {
	_, err := a.db.Exec(`
		INSERT INTO tokens (user_id, access_token, refresh_token, expiry, token_type)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			expiry = EXCLUDED.expiry,
			token_type = EXCLUDED.token_type;
	`, userID, token.AccessToken, token.RefreshToken, token.Expiry, token.TokenType)
	if err != nil {
		log.Printf("saveToken: Error saving token for user %s: %v", userID, err)
	} else {
		log.Printf("saveToken: Token saved/updated for user %s. AccessToken length: %d, RefreshToken present: %t, Expiry: %s",
			userID, len(token.AccessToken), token.RefreshToken != "", token.Expiry.String())
	}
	return err
}

func (a *App) getAuthenticatedClient(userID string) (*http.Client, error) {
	if userID == "" {
		log.Println("getAuthenticatedClient: UserID is empty. Authentication required.")
		return nil, fmt.Errorf("userID is empty. Authentication required")
	}
	log.Printf("getAuthenticatedClient: Attempting to get authenticated client for user %s", userID)
	token, err := a.getToken(userID)
	if err != nil {
		log.Printf("getAuthenticatedClient: Failed to get token for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get token: %v", err)
	}
	if token == nil {
		log.Printf("getAuthenticatedClient: No token found in DB for user %s. User needs to authenticate.", userID)
		return nil, fmt.Errorf("no token found for user %s. Please authenticate via /auth/google/login", userID)
	}

	log.Printf("getAuthenticatedClient: Initial token for user %s: AccessToken length %d, RefreshToken present: %t, Expired: %t",
		userID, len(token.AccessToken), token.RefreshToken != "", !token.Valid())

	tokenSource := a.oauth2Config.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		log.Printf("getAuthenticatedClient: Failed to get fresh token (or refresh failed) for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get fresh token (or refresh failed): %v", err)
	}

	if newToken.AccessToken != token.AccessToken {
		log.Printf("getAuthenticatedClient: Token refreshed for user %s. Saving new token.", userID)
		if err := a.saveToken(userID, newToken); err != nil {
			log.Printf("getAuthenticatedClient: Warning: Failed to save refreshed token for user %s: %v", userID, err)
		}
	} else {
		log.Printf("getAuthenticatedClient: Token for user %s is still valid, no refresh needed.", userID)
	}

	return oauth2.NewClient(context.Background(), tokenSource), nil
}

func getUserIDFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("user_channel_id")
	if err != nil {
		return "", fmt.Errorf("user_channel_id cookie not found: %v", err)
	}
	return cookie.Value, nil
}

func (a *App) handleBusinessAnalytics(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	client := r.Context().Value("authenticated_client").(*http.Client)

	log.Printf("handleBusinessAnalytics: Handling request for user %s (from context)", userID)

	analyticsService, err := youtubeanalytics.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Printf("handleBusinessAnalytics: Error creating YouTube Analytics service: %v", err)
		http.Error(w, fmt.Sprintf("Error creating YouTube Analytics service: %v", err), http.StatusInternalServerError)
		return
	}

	channelID := "channel==MINE"
	endDate := time.Now().Format("2006-01-02")
	startDate := time.Now().AddDate(0, 0, -30).Format("2006-01-02")

	call := analyticsService.Reports.Query().
		Ids(channelID).
		StartDate(startDate).
		EndDate(endDate).
		Metrics("views,subscribersGained").
		Dimensions("day").
		Sort("day")

	response, err := call.Do()
	if err != nil {
		log.Printf("handleBusinessAnalytics: Error fetching business analytics for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error fetching business analytics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	err = a.templates.ExecuteTemplate(w, "analytics_table.html", response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

func (a *App) handleCreatorAnalytics(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	client := r.Context().Value("authenticated_client").(*http.Client)

	log.Printf("handleCreatorAnalytics: Handling request for user %s (from context)", userID)

	reportingService, err := youtubereporting.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Printf("handleCreatorAnalytics: Error creating YouTube Reporting service: %v", err)
		http.Error(w, fmt.Sprintf("Error creating YouTube Reporting service: %v", err), http.StatusInternalServerError)
		return
	}

	reportTypesCall := reportingService.ReportTypes.List()
	reportTypesResp, err := reportTypesCall.Do()
	if err != nil {
		log.Printf("handleCreatorAnalytics: Error listing report types for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error listing report types: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("handleCreatorAnalytics: Available report types for user %s:", userID)
	for _, rt := range reportTypesResp.ReportTypes {
		log.Printf("  - ID: %s, Name: %s", rt.Id, rt.Name)
	}

	var desiredReportTypeID string
	for _, rt := range reportTypesResp.ReportTypes {
		if rt.Id == "channel_basic_a2" {
			desiredReportTypeID = rt.Id
			break
		}
	}

	if desiredReportTypeID == "" {
		log.Printf("handleCreatorAnalytics: Could not find desired report type 'channel_basic_a2' for user %s. Available types: %s", userID, getReportTypeIDs(reportTypesResp))
		http.Error(w, "Could not find a suitable report type (e.g., 'channel_basic_a2'). Ensure your channel has reporting jobs enabled or is eligible for this report type. Check server logs for available types.", http.StatusInternalServerError)
		return
	}

	jobsCall := reportingService.Jobs.List().OnBehalfOfContentOwner(userID)
	jobsResp, err := jobsCall.Do()
	if err != nil {
		log.Printf("handleCreatorAnalytics: Error listing reporting jobs for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error listing reporting jobs: %v", err), http.StatusInternalServerError)
		return
	}

	var jobID string
	for _, job := range jobsResp.Jobs {
		if job.ReportTypeId == desiredReportTypeID {
			jobID = job.Id
			log.Printf("handleCreatorAnalytics: Found existing reporting job: %s for user %s", jobID, userID)
			break
		}
	}

	if jobID == "" {
		newJob := &youtubereporting.Job{
			ReportTypeId: desiredReportTypeID,
			Name:         "MyChannelBasicReport",
		}
		createJobCall := reportingService.Jobs.Create(newJob)
		createdJob, err := createJobCall.Do()
		if err != nil {
			log.Printf("handleCreatorAnalytics: Error creating reporting job for user %s: %v", userID, err)
			http.Error(w, fmt.Sprintf("Error creating reporting job: %v", err), http.StatusInternalServerError)
			return
		}
		jobID = createdJob.Id
		log.Printf("handleCreatorAnalytics: Created new reporting job: %s for user %s", jobID, userID)
	}

	reportsCall := reportingService.Jobs.Reports.List(jobID).
		CreatedAfter(time.Now().AddDate(0, 0, -7).Format(time.RFC3339))

	reportsResp, err := reportsCall.Do()
	if err != nil {
		log.Printf("handleCreatorAnalytics: Error listing reports for job %s (user %s): %v", jobID, userID, err)
		http.Error(w, fmt.Sprintf("Error listing reports for job %s: %v", jobID, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h2 class="text-xl font-bold mb-4 text-gray-800">Content Creator Analytics (Last 7 Days)</h2>`)

	if reportsResp.Reports == nil || len(reportsResp.Reports) == 0 {
		fmt.Fprintf(w, `<p class="text-gray-600">No reports available for the selected period. It might take some time (24-48 hours) for reports to be generated after a job is created. Ensure your Google account has a YouTube channel and that it is active.</p>`)
		return
	}
	fmt.Fprintf(w, `<p class="text-gray-700 mb-2">Available Reports (click to download):</p>`)
	fmt.Fprintf(w, `<ul class="list-disc pl-5 space-y-2">`)
	for _, report := range reportsResp.Reports {
		parsedStartTime, err := time.Parse(time.RFC3339, report.StartTime)
		if err != nil {
			log.Printf("handleCreatorAnalytics: Error parsing report StartTime '%s': %v", report.StartTime, err)
			parsedStartTime = time.Time{}
		}
		parsedEndTime, err := time.Parse(time.RFC3339, report.EndTime)
		if err != nil {
			log.Printf("handleCreatorAnalytics: Error parsing report EndTime '%s': %v", report.EndTime, err)
			parsedEndTime = time.Time{}
		}

		fmt.Fprintf(w, `<li><a href="%s" target="_blank" class="text-blue-600 hover:underline">%s (Start: %s, End: %s)</a></li>`,
			report.DownloadUrl, report.Id, parsedStartTime.Format("2006-01-02"), parsedEndTime.Format("2006-01-02"))
	}
	fmt.Fprintf(w, `</ul>`)

	fmt.Fprintf(w, `<p class="text-gray-700 mt-4">Note: YouTube Reporting API provides reports as downloadable files (e.g., CSV). You would typically download and parse these files to display detailed metrics.</p>`)
}

func getReportTypeIDs(resp *youtubereporting.ListReportTypesResponse) string {
	ids := []string{}
	for _, rt := range resp.ReportTypes {
		ids = append(ids, rt.Id)
	}
	data, _ := json.Marshal(ids)
	return string(data)
}