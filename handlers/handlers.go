package handlers

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/mammenj/ytana/db"
	"github.com/mammenj/ytana/youtubeapi"
	"golang.org/x/oauth2"
)

// Handlers provides access to the application's dependencies for the handlers
type Handlers struct {
	db             *db.DB
	templates      *template.Template
	youtubeService *youtubeapi.Service
}

// NewHandlers creates a new Handlers struct
func NewHandlers(db *db.DB, templates *template.Template, youtubeService *youtubeapi.Service) *Handlers {
	return &Handlers{
		db:             db,
		templates:      templates,
		youtubeService: youtubeService,
	}
}

// TemplateData struct to pass data to the HTML template
type TemplateData struct {
	UserID string
}

func (h *Handlers) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := getUserIDFromCookie(r)
		if err != nil {
			log.Printf("AuthMiddleware: Authentication failed (cookie missing): %v", err)
			http.Error(w, "Authentication required. Please log in.", http.StatusUnauthorized)
			return
		}

		client, err := h.getAuthenticatedClient(userID)
		if err != nil {
			log.Printf("AuthMiddleware: Authentication failed: %v", err)
			http.Error(w, fmt.Sprintf("Authentication required: %v. Please log in.", err), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		ctx = context.WithValue(ctx, "authenticated_client", client)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handlers) ServeIndex(w http.ResponseWriter, r *http.Request) {
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

	err = h.templates.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

func (h *Handlers) HandleYouTubeSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	response, err := h.youtubeService.SearchVideos(query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error searching YouTube: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	log.Printf("handleYouTubeSearch: Found %d results for query '%s'", len(response.Items), query)
	err = h.templates.ExecuteTemplate(w, "search_results.html", response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

func (h *Handlers) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
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

	url := h.youtubeService.OAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	log.Printf("Redirecting to Google for OAuth: %s", url)
	w.Header().Set("HX-Redirect", url)
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
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

	token, err := h.youtubeService.OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("handleGoogleCallback: Error exchanging code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	log.Println("handleGoogleCallback: Token exchange successful.")

	authenticatedUserID, err := h.youtubeService.GetAuthenticatedUserChannelID(token)
	if err != nil {
		log.Printf("handleGoogleCallback: Error getting user channel ID: %v", err)
		http.Error(w, "Failed to get user channel ID", http.StatusInternalServerError)
		return
	}
	log.Printf("handleGoogleCallback: Successfully fetched authenticated user's YouTube Channel ID: %s", authenticatedUserID)

	err = h.db.SaveToken(authenticatedUserID, token)
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

func (h *Handlers) getAuthenticatedClient(userID string) (*http.Client, error) {
	if userID == "" {
		log.Println("getAuthenticatedClient: UserID is empty. Authentication required.")
		return nil, fmt.Errorf("userID is empty. Authentication required")
	}
	log.Printf("getAuthenticatedClient: Attempting to get authenticated client for user %s", userID)
	token, err := h.db.GetToken(userID)
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

	tokenSource := h.youtubeService.OAuthConfig.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		log.Printf("getAuthenticatedClient: Failed to get fresh token (or refresh failed) for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to get fresh token (or refresh failed): %v", err)
	}

	if newToken.AccessToken != token.AccessToken {
		log.Printf("getAuthenticatedClient: Token refreshed for user %s. Saving new token.", userID)
		if err := h.db.SaveToken(userID, newToken); err != nil {
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

func (h *Handlers) HandleBusinessAnalytics(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	client := r.Context().Value("authenticated_client").(*http.Client)

	log.Printf("handleBusinessAnalytics: Handling request for user %s (from context)", userID)

	response, err := h.youtubeService.GetBusinessAnalytics(client)
	if err != nil {
		log.Printf("handleBusinessAnalytics: Error fetching business analytics for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error fetching business analytics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	err = h.templates.ExecuteTemplate(w, "analytics_table.html", response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}

func (h *Handlers) HandleCreatorAnalytics(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	client := r.Context().Value("authenticated_client").(*http.Client)

	log.Printf("handleCreatorAnalytics: Handling request for user %s (from context)", userID)

	data, err := h.youtubeService.GetCreatorAnalytics(client, userID)
	if err != nil {
		log.Printf("handleCreatorAnalytics: Error fetching creator analytics for user %s: %v", userID, err)
		http.Error(w, fmt.Sprintf("Error fetching creator analytics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	err = h.templates.ExecuteTemplate(w, "creator_analytics.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
	}
}
