package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"golang.org/x/oauth2"
	_ "modernc.org/sqlite"
)

// DB represents the database connection
type DB struct {
	*sql.DB
}

// NewDB initializes a new database connection
func NewDB(dataSourceName string) (*DB, error) {
	db, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = createTable(db); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}
	log.Printf("Db connected to: %s", dataSourceName)
	return &DB{db}, nil
}

// createTable creates the 'tokens' table if it doesn't exist
func createTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS tokens (
		user_id TEXT PRIMARY KEY,
		access_token TEXT,
		token_type TEXT,
		refresh_token TEXT,
		expiry DATETIME
	);`
	_, err := db.Exec(query)
	return err
}

// SaveToken saves or updates an OAuth2 token for a given user ID
func (d *DB) SaveToken(userID string, token *oauth2.Token) error {
	log.Printf("Saving token for user: %s", userID)

	query := `
	INSERT INTO tokens (user_id, access_token, token_type, refresh_token, expiry)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(user_id) DO UPDATE SET
		access_token=excluded.access_token,
		token_type=excluded.token_type,
		refresh_token=excluded.refresh_token,
		expiry=excluded.expiry;`

	_, err := d.Exec(query, userID, token.AccessToken, token.TokenType, token.RefreshToken, token.Expiry)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	log.Printf("Token saved successfully for user: %s", userID)
	return nil
}

// GetToken retrieves an OAuth2 token for a given user ID
func (d *DB) GetToken(userID string) (*oauth2.Token, error) {
	log.Printf("Retrieving token for user: %s", userID)
	query := `SELECT access_token, token_type, refresh_token, expiry FROM tokens WHERE user_id = ?;`
	row := d.QueryRow(query, userID)

	var accessToken, tokenType, refreshToken string
	var expiryStr string // Read as string first

	err := row.Scan(&accessToken, &tokenType, &refreshToken, &expiryStr)
	if err == sql.ErrNoRows {
		log.Printf("No token found for user: %s", userID)
		return nil, nil // No token found, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}

	// Parse expiry string back to time.Time
	expiry, err := parseTime(expiryStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry time: %w", err)
	}

	token := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		Expiry:       expiry,
	}
	log.Printf("Token retrieved successfully for user: %s", userID)
	return token, nil
}

// parseTime parses a string into a time.Time object.
// It attempts to parse common SQLite date/time formats.
func parseTime(s string) (t time.Time, err error) {
	layouts := []string{
		"2006-01-02 15:04:05.999999999-07:00", // RFC3339Nano with timezone
		"2006-01-02 15:04:05.999999999",       // RFC3339Nano without timezone
		"2006-01-02 15:04:05",                 // Common SQLite format
		"2006-01-02T15:04:05Z07:00",           // RFC3339
		"2006-01-02T15:04:05Z",                // RFC3339 without timezone
	}

	for _, layout := range layouts {
		t, err = time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse time: %s", s)
}
