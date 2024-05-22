package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kataras/muxie"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/exp/slog"

	"github.com/csunibo/cs-git-login/auth"
	"github.com/csunibo/cs-git-login/util"
)

type Config struct {
	Listen     string   `toml:"listen"`
	BaseURL    string   `toml:"base_url"`
	ClientURLs []string `toml:"client_urls"`

	DbURI                string        `toml:"db_uri" required:"true"`
	OAuthClientID        string        `toml:"oauth_client_id" required:"true"`
	OAuthClientSecret    string        `toml:"oauth_client_secret" required:"true"`
	OAuthSigningKey      string        `toml:"oauth_signing_key" required:"true"`
	OAuthSessionDuration time.Duration `toml:"oauth_session_duration"`
}

var (
	// Default config values
	config = Config{
		Listen:               "0.0.0.0:3000",
		BaseURL:              "http://localhost:3000",
		OAuthSessionDuration: time.Hour * 12,
	}
)

// @title			Login cs github service API
// @version			1.0
// @description		This is a service to handle the login of a user for the csunibo organisation's web-applications.
// @contact.name	Gabriele Genovese
// @contact.email	gabriele.genovese2@studio.unibo.it
// @license.name	AGPL-3.0
// @license.url		https://www.gnu.org/licenses/agpl-3.0.en.html
// @BasePath		/
func main() {
	err := loadConfig()
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	baseURL, err := url.Parse(config.BaseURL)
	if err != nil {
		slog.Error("failed to parse baseURL", "err", err)
		os.Exit(1)
	}

	authenticator := auth.NewAuthenticator(&auth.Config{
		BaseURL:      baseURL,
		ClientID:     config.OAuthClientID,
		ClientSecret: config.OAuthClientSecret,
		SigningKey:   []byte(config.OAuthSigningKey),
		Expiration:   config.OAuthSessionDuration,
	})

	mux := muxie.NewMux()
	mux.Use(util.NewCorsMiddleware(config.ClientURLs, true, mux))

	// authentication api
	mux.HandleFunc("/login", authenticator.LoginHandler)
	mux.HandleFunc("/login/callback", authenticator.CallbackHandler)
	mux.HandleFunc("/logout", authenticator.LogoutHandler)

	// authenticated queries
	mux.Use(authenticator.Middleware)
	mux.HandleFunc("/whoami", auth.WhoAmIHandler)

	slog.Info("listening at", "address", config.Listen)
	err = http.ListenAndServe(config.Listen, mux)
	if err != nil {
		slog.Error("failed to serve", "err", err)
	}
}

func loadConfig() (err error) {
	file, err := os.Open("config.toml")
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}

	err = toml.NewDecoder(file).Decode(&config)
	if err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("failed to close config file: %w", err)
	}

	return nil
}
