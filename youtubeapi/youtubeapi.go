package youtubeapi

import (
	"context"
	"encoding/json"
	"fmt"
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
	"google.golang.org/genai"
)

// Config holds YouTube API specific configuration
type Config struct {
	YouTubeAPIKey      string
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURL        string
	GeminiAPIKey       string
}

// Service encapsulates the YouTube API services.
type Service struct {
	YouTubeAPIKey string
	OAuthConfig   *oauth2.Config
	GenaiClient   *genai.Client
}

// NewConfigFromEnv creates a new Config from environment variables
func NewConfigFromEnv() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, assuming environment variables are set.")
	}

	conf := &Config{
		YouTubeAPIKey:      os.Getenv("YOUTUBE_API_KEY"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:        os.Getenv("REDIRECT_URL"),
		GeminiAPIKey:       os.Getenv("GEMINI_API_KEY"),
	}

	if conf.YouTubeAPIKey == "" {
		return nil, fmt.Errorf("YOUTUBE_API_KEY not set in environment variables")
	}
	if conf.GoogleClientID == "" || conf.GoogleClientSecret == "" || conf.RedirectURL == "" {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or REDIRECT_URL not set for OAuth")
	}
	if conf.GeminiAPIKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY not set in environment variables")
	}

	return conf, nil
}

// NewServiceFromEnv creates a new YouTube API service from environment variables.
func NewServiceFromEnv() (*Service, error) {
	cfg, err := NewConfigFromEnv()
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			youtubeanalytics.YtAnalyticsReadonlyScope,
			"https://www.googleapis.com/auth/yt-analytics.readonly",
			youtube.YoutubeReadonlyScope,
		},
		Endpoint: google.Endpoint,
	}

	ctx := context.Background()
	genaiClient, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  cfg.GeminiAPIKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %v", err)
	}

	return &Service{
		YouTubeAPIKey: cfg.YouTubeAPIKey,
		OAuthConfig:   oauth2Config,
		GenaiClient:   genaiClient,
	}, nil
}

// SearchVideos performs a YouTube search.
func (s *Service) SearchVideos(query string) (*youtube.SearchListResponse, error) {
	ctx := context.Background()
	service, err := youtube.NewService(ctx, option.WithAPIKey(s.YouTubeAPIKey))
	if err != nil {
		return nil, fmt.Errorf("error creating YouTube service: %v", err)
	}

	call := service.Search.List([]string{"id", "snippet"}).
		Q(query).
		MaxResults(10).
		Type("video").Order("viewCount")

	return call.Do()
}

// GetAuthenticatedUserChannelID retrieves the channel ID of the authenticated user.
func (s *Service) GetAuthenticatedUserChannelID(token *oauth2.Token) (string, error) {
	oauthClient := s.OAuthConfig.Client(context.Background(), token)
	youtubeService, err := youtube.NewService(context.Background(), option.WithHTTPClient(oauthClient))
	if err != nil {
		return "", fmt.Errorf("error creating YouTube service: %v", err)
	}

	channelsCall := youtubeService.Channels.List([]string{"id"}).Mine(true)
	channelsResp, err := channelsCall.Do()
	if err != nil {
		return "", fmt.Errorf("error fetching user's channel ID: %v", err)
	}

	if len(channelsResp.Items) > 0 {
		return channelsResp.Items[0].Id, nil
	}

	return "", fmt.Errorf("no YouTube channel found for the authenticated user")
}

// GetBusinessAnalytics fetches business analytics data.
func (s *Service) GetBusinessAnalytics(client *http.Client) (*youtubeanalytics.QueryResponse, error) {
	analyticsService, err := youtubeanalytics.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("error creating YouTube Analytics service: %v", err)
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

	return call.Do()
}

// CreatorAnalyticsData holds data for the creator analytics template.
type CreatorAnalyticsData struct {
	Reports     []*youtubereporting.Report
	ReportLinks []struct {
		URL       string
		ID        string
		StartDate string
		EndDate   string
	}
}

// GetCreatorAnalytics fetches creator analytics data.
func (s *Service) GetCreatorAnalytics(client *http.Client, userID string) (*CreatorAnalyticsData, error) {
	reportingService, err := youtubereporting.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("error creating YouTube Reporting service: %v", err)
	}

	reportTypesCall := reportingService.ReportTypes.List()
	reportTypesResp, err := reportTypesCall.Do()
	if err != nil {
		return nil, fmt.Errorf("error listing report types: %v", err)
	}

	log.Printf("Available report types for user %s:", userID)
	for _, rt := range reportTypesResp.ReportTypes {
		log.Printf("  - ID: %s, Name: %s", rt.Id, rt.Name)
	}

	var desiredReportTypeID string
	for _, rt := range reportTypesResp.ReportTypes {
		if rt.Id == "channel_basic_a3" {
			desiredReportTypeID = rt.Id
			break
		}
	}

	if desiredReportTypeID == "" {
		return nil, fmt.Errorf("could not find desired report type 'channel_basic_a2'. Available types: %s", getReportTypeIDs(reportTypesResp))
	}

	jobsCall := reportingService.Jobs.List().OnBehalfOfContentOwner(userID)
	jobsResp, err := jobsCall.Do()
	if err != nil {
		return nil, fmt.Errorf("error listing reporting jobs: %v", err)
	}

	var jobID string
	for _, job := range jobsResp.Jobs {
		if job.ReportTypeId == desiredReportTypeID {
			jobID = job.Id
			log.Printf("Found existing reporting job: %s for user %s", jobID, userID)
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
			return nil, fmt.Errorf("error creating reporting job: %v", err)
		}
		jobID = createdJob.Id
		log.Printf("Created new reporting job: %s for user %s", jobID, userID)
	}

	reportsCall := reportingService.Jobs.Reports.List(jobID).
		CreatedAfter(time.Now().AddDate(0, 0, -7).Format(time.RFC3339))

	reportsResp, err := reportsCall.Do()
	if err != nil {
		return nil, fmt.Errorf("error listing reports for job %s: %v", jobID, err)
	}

	data := &CreatorAnalyticsData{
		Reports: reportsResp.Reports,
	}

	for _, report := range reportsResp.Reports {
		parsedStartTime, err := time.Parse(time.RFC3339, report.StartTime)
		if err != nil {
			log.Printf("Error parsing report StartTime '%s': %v", report.StartTime, err)
			parsedStartTime = time.Time{}
		}
		parsedEndTime, err := time.Parse(time.RFC3339, report.EndTime)
		if err != nil {
			log.Printf("Error parsing report EndTime '%s': %v", report.EndTime, err)
			parsedEndTime = time.Time{}
		}
		data.ReportLinks = append(data.ReportLinks, struct {
			URL       string
			ID        string
			StartDate string
			EndDate   string
		}{
			URL:       report.DownloadUrl,
			ID:        report.Id,
			StartDate: parsedStartTime.Format("2006-01-02"),
			EndDate:   parsedEndTime.Format("2006-01-02"),
		})
	}

	return data, nil
}

func getReportTypeIDs(resp *youtubereporting.ListReportTypesResponse) string {
	ids := []string{}
	for _, rt := range resp.ReportTypes {
		ids = append(ids, rt.Id)
	}
	data, _ := json.Marshal(ids)
	return string(data)
}

// GetVideoSentiment analyzes the sentiment of a video from a URL.
func (s *Service) GetVideoSentiment(ctx context.Context, url string) (string, error) {
	// ctx := context.Background()
	parts := []*genai.Part{
		genai.NewPartFromText("Please provide the sentiment on scale of 1 to 5, 5 being the most postive and summarize in one or two sentence."),
		genai.NewPartFromURI(url, "video/mp4"),
	}

	contents := []*genai.Content{
		genai.NewContentFromParts(parts, genai.RoleUser),
	}

	result, _ := s.GenaiClient.Models.GenerateContent(
		ctx,
		"gemini-2.5-flash",
		contents,
		nil,
	)
	//	sentiment := result.Text()
	// log.Printf("Sentiment analysis result: %s", sentiment)

	/////

	if result == nil {
		return "", fmt.Errorf("received an empty response from the sentiment analysis model")
	}

	sentiment := result.Text()
	log.Printf("Sentiment analysis result: %s", sentiment)

	return sentiment, nil
}
