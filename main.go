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

	"github.com/joho/godotenv"      // For loading environment variables from .env file
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/youtube/v3"
	"google.golang.org/api/youtubeanalytics/v2"
	"google.golang.org/api/youtubereporting/v1"
)

// Config holds application configuration from environment variables
type Config struct {
	YouTubeAPIKey      string
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURL        string
	DatabasePath       string
}

// Token represents an OAuth token stored in the database
type Token struct {
	ID           int
	UserID       string // A simple identifier for the user (e.g., a session ID or a unique user ID)
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	TokenType    string
}

// Global variables for database and OAuth config
var (
	db           *sql.DB
	conf         *Config
	oauth2Config *oauth2.Config
)

// init loads environment variables and initializes the database
func init() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, assuming environment variables are set.")
	}

	conf = &Config{
		YouTubeAPIKey:      os.Getenv("YOUTUBE_API_KEY"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:        os.Getenv("REDIRECT_URL"),
		DatabasePath:       os.Getenv("DATABASE_PATH"),
	}

	if conf.YouTubeAPIKey == "" {
		log.Fatal("YOUTUBE_API_KEY not set in environment variables.")
	}
	if conf.GoogleClientID == "" || conf.GoogleClientSecret == "" || conf.RedirectURL == "" {
		log.Fatal("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or REDIRECT_URL not set for OAuth.")
	}
	if conf.DatabasePath == "" {
		conf.DatabasePath = "./youtube_app.db" // Default database path
	}

	// Initialize OAuth2 config
	oauth2Config = &oauth2.Config{
		ClientID:     conf.GoogleClientID,
		ClientSecret: conf.GoogleClientSecret,
		RedirectURL:  conf.RedirectURL,
		Scopes: []string{
			youtubeanalytics.YtAnalyticsReadonlyScope,
			"https://www.googleapis.com/auth/yt-analytics.readonly", // Explicit scope for Reporting API
			youtube.YoutubeReadonlyScope,                            // For general channel info if needed
		},
		Endpoint: google.Endpoint,
	}

	// Initialize SQLite database
	var err error
	db, err = sql.Open("sqlite3", conf.DatabasePath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	// Create tokens table if it doesn't exist
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
		log.Fatalf("Error creating tokens table: %v", err)
	}
	log.Printf("Database initialized at %s", conf.DatabasePath)
}

func main() {
	// Serve static files (CSS, JS if any) - not strictly needed for this HTMX/Alpine setup but good practice
	// http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/search", handleYouTubeSearch)
	http.HandleFunc("/auth/google/login", handleGoogleLogin)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)
	http.HandleFunc("/business", handleBusinessAnalytics)
	http.HandleFunc("/creator", handleCreatorAnalytics)

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// serveIndex serves the main HTML page
func serveIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing template: %v", err), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// handleYouTubeSearch handles video search requests using YouTube Data API
func handleYouTubeSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	service, err := youtube.NewService(ctx, option.WithAPIKey(conf.YouTubeAPIKey))
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating YouTube service: %v", err), http.StatusInternalServerError)
		return
	}

	call := service.Search.List([]string{"id", "snippet"}).
		Q(query).
		MaxResults(10). // Limit results for brevity
		Type("video")

	response, err := call.Do()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error searching YouTube: %v", err), http.StatusInternalServerError)
		return
	}

	// Render search results as HTML snippets for HTMX
	w.Header().Set("Content-Type", "text/html")
	for _, item := range response.Items {
		videoID := item.Id.VideoId
		title := item.Snippet.Title
		description := item.Snippet.Description
		thumbnail := item.Snippet.Thumbnails.Default.Url

		fmt.Fprintf(w, `
			<div class="p-4 border-b border-gray-200 flex items-start space-x-4 rounded-lg shadow-sm mb-4 bg-white">
				<img src="%s" alt="%s" class="w-24 h-auto rounded-md object-cover">
				<div>
					<h3 class="font-semibold text-lg text-blue-700 hover:underline"><a href="https://www.youtube.com/watch?v=%s" target="_blank">%s</a></h3>
					<p class="text-gray-600 text-sm mt-1">%s</p>
				</div>
			</div>
		`, thumbnail, title, videoID, title, description)
	}
}

// handleGoogleLogin redirects to Google's OAuth consent screen
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate a random state string to prevent CSRF attacks
	state := "random-state-string" // In a real app, generate a cryptographically secure random string and store it in a session.
	url := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleGoogleCallback handles the redirect from Google after user authorization
func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Received callback from Google OAuth.") // New log message
	state := r.FormValue("state")
	if state != "random-state-string" { // Validate state
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Error exchanging code for token: %v", err) // More specific log
		http.Error(w, fmt.Sprintf("Error exchanging code for token: %v", err), http.StatusInternalServerError)
		return
	}

	// For simplicity, we'll use a fixed user ID or session ID. In a real app, this would be tied to your user management system.
	userID := "current_user_id" // Replace with actual user ID from your session/auth system

	// Save token to database
	err = saveToken(userID, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving token: %v", err), http.StatusInternalServerError)
		return
	}

	// Redirect to the main page or a success page
	http.Redirect(w, r, "/", http.StatusFound)
}

// getToken retrieves a token from the database for a given user ID
func getToken(userID string) (*oauth2.Token, error) {
	row := db.QueryRow("SELECT access_token, refresh_token, expiry, token_type FROM tokens WHERE user_id = ?", userID)
	var accessToken, refreshToken, tokenType string
	var expiry time.Time
	err := row.Scan(&accessToken, &refreshToken, &expiry, &tokenType)
	if err == sql.ErrNoRows {
		log.Printf("No token found in DB for user %s", userID)
		return nil, nil // No token found
	}
	if err != nil {
		return nil, fmt.Errorf("error scanning token from DB: %v", err)
	}

	log.Printf("Retrieved token from DB for user %s. Expiry: %s, RefreshToken present: %t", userID, expiry.String(), refreshToken != "")
	return &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       expiry,
		TokenType:    tokenType,
	}, nil
}

// saveToken saves or updates a token in the database
func saveToken(userID string, token *oauth2.Token) error {
	_, err := db.Exec(`
		INSERT INTO tokens (user_id, access_token, refresh_token, expiry, token_type)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			expiry = EXCLUDED.expiry,
			token_type = EXCLUDED.token_type;
	`, userID, token.AccessToken, token.RefreshToken, token.Expiry, token.TokenType)
	if err != nil {
		log.Printf("Error saving token for user %s: %v", userID, err)
	} else {
		log.Printf("Token saved/updated for user %s. Expiry: %s", userID, token.Expiry.String())
	}
	return err
}

// getAuthenticatedClient creates an HTTP client with the user's OAuth token
func getAuthenticatedClient(userID string) (*http.Client, error) {
	log.Printf("Attempting to get authenticated client for user %s", userID)
	token, err := getToken(userID)
	if err != nil {
		log.Printf("Failed to get token for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get token: %v", err)
	}
	if token == nil {
		log.Printf("No token found for user %s. User needs to authenticate.", userID)
		return nil, fmt.Errorf("no token found for user %s. Please authenticate via /auth/google/login", userID)
	}

	log.Printf("Initial token for user %s: AccessToken length %d, RefreshToken present: %t, Expired: %t",
		userID, len(token.AccessToken), token.RefreshToken != "", !token.Valid())

	// Create a token source that automatically refreshes the token if expired
	tokenSource := oauth2Config.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token() // This will refresh if expired
	if err != nil {
		log.Printf("Failed to get fresh token (or refresh failed) for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get fresh token (or refresh failed): %v", err)
	}

	// If the token was refreshed, save the new one
	if newToken.AccessToken != token.AccessToken {
		log.Printf("Token refreshed for user %s. Saving new token.", userID)
		if err := saveToken(userID, newToken); err != nil {
			log.Printf("Warning: Failed to save refreshed token for user %s: %v", userID, err)
		}
	} else {
		log.Printf("Token for user %s is still valid, no refresh needed.", userID)
	}

	return oauth2.NewClient(context.Background(), tokenSource), nil
}

// handleBusinessAnalytics fetches and displays YouTube Analytics data for businesses
func handleBusinessAnalytics(w http.ResponseWriter, r *http.Request) {
	userID := "current_user_id" // Replace with actual user ID
	log.Printf("Handling /business request for user %s", userID)
	client, err := getAuthenticatedClient(userID)
	if err != nil {
		log.Printf("Authentication failed for /business: %v", err)
		http.Error(w, fmt.Sprintf("Authentication required: %v. Please log in.", err), http.StatusUnauthorized)
		return
	}

	analyticsService, err := youtubeanalytics.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Printf("Error creating YouTube Analytics service: %v", err)
		http.Error(w, fmt.Sprintf("Error creating YouTube Analytics service: %v", err), http.StatusInternalServerError)
		return
	}

	channelID := "channel==MINE" // Special value for the authenticated user's channel

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
		log.Printf("Error fetching business analytics for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error fetching business analytics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h2 class="text-xl font-bold mb-4 text-gray-800">Business Analytics (Last 30 Days)</h2>`)
	if response.Rows == nil || len(response.Rows) == 0 {
		fmt.Fprintf(w, `<p class="text-gray-600">No data available for the selected period. Ensure your Google account has a YouTube channel associated with it and that it has analytics data.</p>`)
		return
	}

	fmt.Fprintf(w, `<div class="overflow-x-auto"><table class="min-w-full bg-white rounded-lg shadow-md">
		<thead>
			<tr class="bg-gray-100 text-left text-gray-600 uppercase text-sm leading-normal">
				<th class="py-3 px-6">Date</th>
				<th class="py-3 px-6">Views</th>
				<th class="py-3 px-6">Subscribers Gained</th>
			</tr>
		</thead>
		<tbody class="text-gray-700 text-sm">`)
	for _, row := range response.Rows {
		date := row[0].(string)
		views := row[1].(float64)
		subscribersGained := row[2].(float64)
		fmt.Fprintf(w, `
			<tr class="border-b border-gray-200 hover:bg-gray-50">
				<td class="py-3 px-6">%s</td>
				<td class="py-3 px-6">%.0f</td>
				<td class="py-3 px-6">%.0f</td>
			</tr>
		`, date, views, subscribersGained)
	}
	fmt.Fprintf(w, `</tbody></table></div>`)
}

// handleCreatorAnalytics fetches and displays YouTube Reporting data for content creators
func handleCreatorAnalytics(w http.ResponseWriter, r *http.Request) {
	userID := "current_user_id" // Replace with actual user ID
	log.Printf("Handling /creator request for user %s", userID)
	client, err := getAuthenticatedClient(userID)
	if err != nil {
		log.Printf("Authentication failed for /creator: %v", err)
		http.Error(w, fmt.Sprintf("Authentication required: %v. Please log in.", err), http.StatusUnauthorized)
		return
	}

	reportingService, err := youtubereporting.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Printf("Error creating YouTube Reporting service: %v", err)
		http.Error(w, fmt.Sprintf("Error creating YouTube Reporting service: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 1: List report types to find available reports
	reportTypesCall := reportingService.ReportTypes.List()
	reportTypesResp, err := reportTypesCall.Do()
	if err != nil {
		log.Printf("Error listing report types for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error listing report types: %v", err), http.StatusInternalServerError)
		return
	}

	var desiredReportTypeID string
	// Find a suitable report type, e.g., "channel_basic_a2" for basic channel activity
	for _, rt := range reportTypesResp.ReportTypes {
		if rt.Id == "channel_basic_a2" { // Example report type for basic channel activity
			desiredReportTypeID = rt.Id
			break
		}
	}

	if desiredReportTypeID == "" {
		log.Printf("Could not find desired report type 'channel_basic_a2' for user %s. Available types: %s", userID, getReportTypeIDs(reportTypesResp))
		http.Error(w, "Could not find a suitable report type (e.g., 'channel_basic_a2'). Ensure your channel has reporting jobs enabled or is eligible for this report type.", http.StatusInternalServerError)
		return
	}

	// Step 2: Create a reporting job
	// In a real application, you'd create this job once and then retrieve reports from it.
	// For this example, we'll try to get existing jobs or create a new one.
	jobsCall := reportingService.Jobs.List()
	jobsResp, err := jobsCall.Do()
	if err != nil {
		log.Printf("Error listing reporting jobs for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error listing reporting jobs: %v", err), http.StatusInternalServerError)
		return
	}

	var jobID string
	// Try to find an existing job for the desired report type
	for _, job := range jobsResp.Jobs {
		if job.ReportTypeId == desiredReportTypeID {
			jobID = job.Id
			log.Printf("Found existing reporting job: %s for user %s", jobID, userID)
			break
		}
	}

	if jobID == "" {
		// If no job exists, create a new one
		newJob := &youtubereporting.Job{
			ReportTypeId: desiredReportTypeID,
			Name:         "MyChannelBasicReport", // A user-friendly name for the job
		}
		createJobCall := reportingService.Jobs.Create(newJob)
		createdJob, err := createJobCall.Do()
		if err != nil {
			log.Printf("Error creating reporting job for user %s: %v", userID, err)
			http.Error(w, fmt.Sprintf("Error creating reporting job: %v", err), http.StatusInternalServerError)
			return
		}
		jobID = createdJob.Id
		log.Printf("Created new reporting job: %s for user %s", jobID, userID)
		// Note: Newly created jobs might not have data immediately. It takes time for reports to be generated.
		// For a real app, you'd check for reports periodically.
		// For this demo, we might not see data immediately after creating a new job.
	}

	// Step 3: List reports for the job
	reportsCall := reportingService.Jobs.Reports.List(jobID).
		CreatedAfter(time.Now().AddDate(0, 0, -7).Format(time.RFC3339))

	reportsResp, err := reportsCall.Do()
	if err != nil {
		log.Printf("Error listing reports for job %s (user %s): %v", jobID, userID, err)
		http.Error(w, fmt.Sprintf("Error listing reports for job %s: %v", jobID, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h2 class="text-xl font-bold mb-4 text-gray-800">Content Creator Analytics (Last 7 Days)</h2>`)

	if reportsResp.Reports == nil || len(reportsResp.Reports) == 0 {
		fmt.Fprintf(w, `<p class="text-gray-600">No reports available for the selected period. It might take some time (24-48 hours) for reports to be generated after a job is created. Ensure your Google account has a YouTube channel and that it is active.</p>`)
		return
	}

	// For simplicity, we'll just display links to the report URLs.
	// In a real application, you would download the CSV/JSON report from these URLs and parse them.
	fmt.Fprintf(w, `<p class="text-gray-700 mb-2">Available Reports (click to download):</p>`)
	fmt.Fprintf(w, `<ul class="list-disc pl-5 space-y-2">`)
	for _, report := range reportsResp.Reports {
		// Parse StartTime and EndTime strings into time.Time objects before formatting
		parsedStartTime, err := time.Parse(time.RFC3339, report.StartTime)
		if err != nil {
			log.Printf("Error parsing report StartTime '%s': %v", report.StartTime, err)
			parsedStartTime = time.Time{} // Use zero time on error
		}
		parsedEndTime, err := time.Parse(time.RFC3339, report.EndTime)
		if err != nil {
			log.Printf("Error parsing report EndTime '%s': %v", report.EndTime, err)
			parsedEndTime = time.Time{} // Use zero time on error
		}

		fmt.Fprintf(w, `<li><a href="%s" target="_blank" class="text-blue-600 hover:underline">%s (Start: %s, End: %s)</a></li>`,
			report.DownloadUrl, report.Id, parsedStartTime.Format("2006-01-02"), parsedEndTime.Format("2006-01-02"))
	}
	fmt.Fprintf(w, `</ul>`)

	fmt.Fprintf(w, `<p class="text-gray-700 mt-4">Note: YouTube Reporting API provides reports as downloadable files (e.g., CSV). You would typically download and parse these files to display detailed metrics.</p>`)
}

// Helper to get report type IDs for error messages
func getReportTypeIDs(resp *youtubereporting.ListReportTypesResponse) string {
	ids := []string{}
	for _, rt := range resp.ReportTypes {
		ids = append(ids, rt.Id)
	}
	data, _ := json.Marshal(ids)
	return string(data)
}
