package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/mammenj/ytana/db"
	"github.com/mammenj/ytana/handlers"
	"github.com/mammenj/ytana/youtubeapi"
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

	h := handlers.NewHandlers(app.db, app.templates, app.youtubeService)

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.ServeIndex)
	mux.HandleFunc("/search", h.HandleYouTubeSearch)
	mux.HandleFunc("/auth/google/login", h.HandleGoogleLogin)
	mux.HandleFunc("/auth/google/callback", h.HandleGoogleCallback)
	mux.Handle("/business", h.AuthMiddleware(http.HandlerFunc(h.HandleBusinessAnalytics)))
	mux.Handle("/creator", h.AuthMiddleware(http.HandlerFunc(h.HandleCreatorAnalytics)))
	mux.HandleFunc("/sentiment", h.HandleSentimentAnalysis)

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}