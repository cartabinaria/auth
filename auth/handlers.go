package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cartabinaria/auth/pkg/httputil"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
)

type StateWithReturnTo struct {
	ReturnTo string `json:"return_to"`
	CSRF     string `json:"csrf"`
}

func decodeState(encodedState string) (StateWithReturnTo, error) {
	var state StateWithReturnTo

	stateBytes, err := base64.URLEncoding.DecodeString(encodedState)
	if err != nil {
		slog.Error("Failed to decode base64 state", "error", err)
		return state, fmt.Errorf("failed to decode state: %w", err)
	}

	if err := json.Unmarshal(stateBytes, &state); err != nil {
		slog.Error("Failed to unmarshal JSON state", "error", err)
		return state, fmt.Errorf("failed to unmarshal state json: %w", err)
	}

	return state, nil
}

// @Summary		Login Callback
// @Description	CallbackHandler handles the OAuth callback, obtaining the GitHub's Bearer token
// @Description	for the logged-in user, and generating a wrapper JWT for our session.
// @Tags			login
// @Param			code			query		string	true	"code query parameter"
// @Param			redirect_uri	query		string	true	"url to redirect if login is successful"
// @Success		200				{object}	string
// @Failure		400				{object}	httputil.ApiError
// @Router			/login/callback [get]
func (a *Authenticator) CallbackHandler(res http.ResponseWriter, req *http.Request) {
	// Check the state query parameter for CSRF attacks
	state := req.URL.Query().Get("state")
	oauthState, err := req.Cookie("oauthstate")
	if err != nil {
		httputil.WriteError(res, http.StatusBadRequest, "missing state cookie")
		slog.Error("missing oauthstate cookie", "error", err)
		return
	}

	// Invalidate the cookie after checking it
	http.SetCookie(res, &http.Cookie{
		Name:     "oauthstate",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   a.cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Path:     "/",
	})

	queryState, err := decodeState(state)
	if err != nil {
		slog.Error("error while decoding query state", "error", err)
		httputil.WriteError(res, http.StatusInternalServerError, "error")
		return
	}

	cookieState, err := decodeState(oauthState.Value)
	if err != nil {
		slog.Error("error while decoding oauth state", "error", err)
		httputil.WriteError(res, http.StatusInternalServerError, "error")
		return
	}

	if queryState.CSRF != cookieState.CSRF {
		httputil.WriteError(res, http.StatusBadRequest, "error")
		slog.Error("invalid csrf token", "expected", cookieState.CSRF, "got", queryState.CSRF)
		return
	}

	if queryState.ReturnTo != cookieState.ReturnTo {
		httputil.WriteError(res, http.StatusBadRequest, "error")
		slog.Error("invalid return_to parameter", "expected", cookieState.ReturnTo, "got", queryState.ReturnTo)
		return
	}

	query := req.URL.Query()
	if query.Has("error") {
		httputil.WriteError(res, http.StatusInternalServerError, "internal error while parsing the callback")
		slog.Error("error while parsing redirect callback",
			"error", query.Get("error"),
			"description", query.Get("error_description"),
			"uri", query.Get("error_uri"))
		return
	}

	authCode := query.Get("code")
	if authCode == "" {
		httputil.WriteError(res, http.StatusBadRequest, "missing the code query parameter")
		return
	}

	redirectURIString := query.Get("redirect_uri")
	if redirectURIString == "" {
		httputil.WriteError(res, http.StatusBadRequest, "missing the redirect_uri query parameter")
		return
	}

	redirectURI, err := url.Parse(redirectURIString)
	if err != nil {
		httputil.WriteError(res, http.StatusBadRequest, "invalid redirect_uri")
		slog.Error("invalid redirect_uri", "error", err)
		return
	}

	token, err := a.getToken(authCode)
	if err != nil {
		httputil.WriteError(res, http.StatusBadRequest, "could not fetch the bearer token from GitHub")
		slog.Error("error while getting the bearer token", "error", err)
		return
	}

	user, err := a.getUser(token, res, req)
	if err != nil {
		httputil.WriteError(res, http.StatusInternalServerError, "could not fetch the user data from GitHub")
		slog.Error("error while fetching user data from github", "error", err)
		return
	}

	iat := time.Now().Add(-1 * time.Minute) // 1 min in the past to allow for clock drift
	exp := iat.Add(a.expiration)

	claims := jwt.MapClaims{
		"iat":   iat.Unix(),
		"exp":   exp.Unix(),
		"token": token,
		"user":  user,
		"id":    user.ID,
	}

	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.signingKey)
	if err != nil {
		httputil.WriteError(res, http.StatusInternalServerError, "could not sign session token")
		return
	}

	cookie := http.Cookie{
		Name:     "auth",
		Value:    tokenString,
		Expires:  time.Now().Add(a.expiration),
		Domain:   a.cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Path:     "/",
	}

	redirectQuery := url.Values{}
	redirectQuery.Set("session_token", tokenString)
	redirectQuery.Set("return_to", cookieState.ReturnTo)

	redirectURI.RawQuery = redirectQuery.Encode()

	http.SetCookie(res, &cookie)
	http.Redirect(res, req, redirectURI.String(), http.StatusSeeOther)
}

// @Summary		Login user
// @Description	LoginHandler handles login requests, redirecting the web client to GitHub's first stage
// @Description	for the OAuth flow, where the user has to grant access to the specified scopes
// @Tags			login
// @Param			redirect_uri	query		string	true	"url to redirect if login is successful"	Url
// @Success		200				{object}	string
// @Failure		400				{object}	httputil.ApiError
// @Router			/login [get]
func (a *Authenticator) LoginHandler(res http.ResponseWriter, req *http.Request) {
	// Get the client redirect url
	clientRedirectURL := req.URL.Query().Get("redirect_uri")
	returnTo := req.URL.Query().Get("return_to")
	if clientRedirectURL == "" {
		httputil.WriteError(res, http.StatusBadRequest, "specify a redirect_uri url param")
		return
	}

	// Create the url query
	query := url.Values{}
	query.Set("redirect_uri", clientRedirectURL)

	// Create the callback url
	redirectCallbackURL := *a.baseURL // Clone the BaseURL so we don't modify it
	redirectCallbackURL.Path = "/login/callback"
	redirectCallbackURL.RawQuery = query.Encode()

	// Create the authorization url
	redirectURL := *GithubAuthorizeURL
	query = redirectURL.Query()
	query.Set("client_id", a.clientID)
	query.Set("redirect_uri", redirectCallbackURL.String())
	query.Set("scope", SCOPES)

	// Generate random state
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		httputil.WriteError(res, http.StatusInternalServerError, "could not generate state")
		slog.Error("could not generate random bytes for state", "error", err)
		return
	}

	csrf := base64.RawURLEncoding.EncodeToString(b)

	// include return_to into github URL
	stateObj := StateWithReturnTo{
		CSRF:     csrf,
		ReturnTo: returnTo,
	}

	stateJSON, err := json.Marshal(stateObj)
	if err != nil {
		slog.Error("could not create json object for state", "error", err)
	}

	// url encoding
	state := base64.RawURLEncoding.EncodeToString(stateJSON)

	// Set state in a cookie
	http.SetCookie(res, &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	// Add state to the authorization url
	query.Set("state", state)
	redirectURL.RawQuery = query.Encode()

	http.Redirect(res, req, redirectURL.String(), http.StatusSeeOther)
}

// @Summary		Logout user
// @Description	Reset the cookie
// @Tags			login
// @Param			redirect_uri	query		string	true	"url to redirect if login is successful"	Url
// @Success		200				{object}	string
// @Failure		400				{object}	httputil.ApiError
// @Router			/logout [get]
func (a *Authenticator) LogoutHandler(res http.ResponseWriter, req *http.Request) {
	// Get the client redirect url
	clientRedirectURL := req.URL.Query().Get("redirect_uri")
	if clientRedirectURL == "" {
		httputil.WriteError(res, http.StatusBadRequest, "specify a redirect_uri url param")
		return
	}

	// Create the url query
	query := url.Values{}
	query.Set("redirect_uri", clientRedirectURL)

	cookie := http.Cookie{
		Name:     "auth",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   a.cookieDomain,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(res, &cookie)
	http.Redirect(res, req, clientRedirectURL, http.StatusSeeOther)
}

func (a *Authenticator) CheckMembership(token string, login string) (string, error) {
	reqHttp, err := http.NewRequest(http.MethodGet, GithubMemberURL.JoinPath(login).String(), nil)
	if err != nil {
		return "", fmt.Errorf("could not construct GitHub's user request: %w", err)
	}
	reqHttp.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	reqHttp.Header.Set("Accept", "application/vnd.github+json")

	resHttp, err := client.Do(reqHttp)
	if err != nil {
		if resHttp.StatusCode == http.StatusNotFound {
			return "user", nil
		}
		return "", fmt.Errorf("could not send GitHub's user request: %w", err)
	}
	var githubRes GithubMemberUserResponse
	err = json.NewDecoder(resHttp.Body).Decode(&githubRes)
	if err != nil {
		return "", fmt.Errorf("could not parse GitHub's response: %w", err)
	}

	err = resHttp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("could not close body: %w", err)
	}

	return githubRes.Role, nil
}
