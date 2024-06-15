package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/csunibo/auth"
)

const (
	SCOPES = "read:user,user:email,read:org,read:members"
)

var (
	GithubAuthorizeURL, _   = url.Parse("https://github.com/login/oauth/authorize")
	GithubAccessTokenURL, _ = url.Parse("https://github.com/login/oauth/access_token")
	GithubUserURL, _        = url.Parse("https://api.github.com/user")
	GithubMemberURL, _      = url.Parse("https://api.github.com/orgs/csunibo/memberships/")
	client                  = http.DefaultClient
)

type Config struct {
	ClientID     string        // The OAuth client ID
	ClientSecret string        // The OAuth client secret
	BaseURL      *url.URL      // The base URL from where csunibo/upld is being served from
	SigningKey   []byte        // The key to sign the JWTs with
	Expiration   time.Duration // How long should user sessions last?
}

type Authenticator struct {
	clientID     string
	clientSecret string
	baseURL      *url.URL
	expiration   time.Duration
	signingKey   []byte
}

func NewAuthenticator(config *Config) *Authenticator {
	authenticator := Authenticator{
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		baseURL:      config.BaseURL,
		signingKey:   config.SigningKey,
		expiration:   config.Expiration,
	}
	return &authenticator
}

type GithubData struct {
	payload    string
	authorized bool
}

// GithubAccessTokenRequest is the request we send to GitHub to request for a token
type GithubAccessTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
}

// GithubAccessTokenResponse is the response received from GitHub when requesting for a token
type GithubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// getToken requests GitHub for a token to act on the behalf of a user, provided
// we have received the authentication code for the user. That, is generated after
// the user accepts to log in without OAuth API and gets redirected to our callback.
func (a *Authenticator) getToken(authCode string) (string, error) {
	tokenRequest := GithubAccessTokenRequest{
		ClientId:     a.clientID,
		ClientSecret: a.clientSecret,
		Code:         authCode,
	}

	body, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", fmt.Errorf("could not serialize JSON request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, GithubAccessTokenURL.String(), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("error while constructing the request to GitHub: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error while sending the request to GitHub: %w", err)
	}

	var githubRes GithubAccessTokenResponse
	err = json.NewDecoder(res.Body).Decode(&githubRes)
	if err != nil {
		return "", fmt.Errorf("error while parsing GitHub's response: %w", err)
	}

	return githubRes.AccessToken, nil
}

type GithubUserResponse struct {
	Id        int    `json:"id"`
	Name      string `json:"name"`
	AvatarUrl string `json:"avatar_url"`
	Email     string `json:"email"`
	Login     string `json:"login"`
	Url       string `json:"url"`
}
type GithubMemberUserResponse struct {
	Message string `json:"message,omitempty"`
	Role    string `json:"role,omitempty"`
}

func (a *Authenticator) getUser(token string, res http.ResponseWriter, req *http.Request) (*auth.User, error) {
	reqHttp, err := http.NewRequest(http.MethodGet, GithubUserURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not construct GitHub's user request: %w", err)
	}

	reqHttp.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resHttp, err := client.Do(reqHttp)
	if err != nil {
		return nil, fmt.Errorf("could not send GitHub's user request: %w", err)
	}

	var githubRes GithubUserResponse
	err = json.NewDecoder(resHttp.Body).Decode(&githubRes)
	if err != nil {
		return nil, fmt.Errorf("could not parse GitHub's response: %w", err)
	}

	err = resHttp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("could not close body: %w", err)
	}

	admin, err := a.CheckMembership(token, githubRes.Login)
	if err != nil {
		return nil, fmt.Errorf("could not check admin: %w", err)
	}

	return &auth.User{
		Username:  githubRes.Login,
		AvatarUrl: githubRes.AvatarUrl,
		Name:      githubRes.Name,
		Email:     githubRes.Email,
		Admin:     admin,
	}, nil
}
