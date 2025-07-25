package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/mammenj/ytana/db"
	"github.com/mammenj/ytana/youtubeapi"
	"golang.org/x/oauth2"
)

// Config holds application configuration from environment variables
type Config struct {
	DatabasePath string
}

// App holds the application's dependencies
type App struct {
	db             *db.DB
	conf           *Config
	templates      *template.Template
	youtubeService *youtubeapi.Service
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
		DatabasePath: os.Getenv("DATABASE_PATH"),
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

	db, err := db.NewDB(conf.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("error initializing database: %v", err)
	}

	youtubeService, err := youtubeapi.NewServiceFromEnv()
	if err != nil {
		return nil, fmt.Errorf("error creating youtube service: %v", err)
	}

	templates, err := template.ParseGlob("templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %v", err)
	}

	return &App{
		db:             db,
		conf:           conf,
		templates:      templates,
		youtubeService: youtubeService,
	}, nil
}

func main() {
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer app.db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.serveIndex)
	mux.HandleFunc("/search", app.handleYouTubeSearch)
	mux.HandleFunc("/auth/google/login", app.handleGoogleLogin)
	mux.HandleFunc("/auth/google/callback", app.handleGoogleCallback)
	mux.Handle("/business", app.authMiddleware(http.HandlerFunc(app.handleBusinessAnalytics)))
	mux.Handle("/creator", app.authMiddleware(http.HandlerFunc(app.handleCreatorAnalytics)))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
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

	response, err := a.youtubeService.SearchVideos(query)
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

	url := a.youtubeService.OAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
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

	token, err := a.youtubeService.OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("handleGoogleCallback: Error exchanging code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	log.Println("handleGoogleCallback: Token exchange successful.")

	authenticatedUserID, err := a.youtubeService.GetAuthenticatedUserChannelID(token)
	if err != nil {
		log.Printf("handleGoogleCallback: Error getting user channel ID: %v", err)
		http.Error(w, "Failed to get user channel ID", http.StatusInternalServerError)
		return
	}
	log.Printf("handleGoogleCallback: Successfully fetched authenticated user's YouTube Channel ID: %s", authenticatedUserID)

	err = a.db.SaveToken(authenticatedUserID, token)
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

func (a *App) getAuthenticatedClient(userID string) (*http.Client, error) {
	if userID == "" {
		log.Println("getAuthenticatedClient: UserID is empty. Authentication required.")
		return nil, fmt.Errorf("userID is empty. Authentication required")
	}
	log.Printf("getAuthenticatedClient: Attempting to get authenticated client for user %s", userID)
	token, err := a.db.GetToken(userID)
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

	tokenSource := a.youtubeService.OAuthConfig.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		log.Printf("getAuthenticatedClient: Failed to get fresh token (or refresh failed) for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get fresh token (or refresh failed): %v", err)
	}

	if newToken.AccessToken != token.AccessToken {
		log.Printf("getAuthenticatedClient: Token refreshed for user %s. Saving new token.", userID)
		if err := a.db.SaveToken(userID, newToken); err != nil {
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

	response, err := a.youtubeService.GetBusinessAnalytics(client)
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

	data, err := a.youtubeService.GetCreatorAnalytics(client, userID)
	if err != nil {
		log.Printf("handleCreatorAnalytics: Error fetching creator analytics for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error fetching creator analytics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	err = a.templates.ExecuteTemplate(w, "creator_analytics.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

