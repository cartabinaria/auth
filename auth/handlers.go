package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/csunibo/auth/pkg/httputil"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
)

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
	// TODO: Check the state query parameter for CSRF attacks

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

	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		httputil.WriteError(res, http.StatusBadRequest, "missing the redirect_uri query parameter")
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
		Secure:   false,
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(res, &cookie)
	http.Redirect(res, req, redirectURI, http.StatusSeeOther)
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
	redirectURL.RawQuery = query.Encode()

	// TODO: add the state query parameter to protect against CSRF

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
		Secure:   false,
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(res, &cookie)
	http.Redirect(res, req, clientRedirectURL, http.StatusSeeOther)
}

func (a *Authenticator) CheckMembership(token string, login string) (bool, error) {
	reqHttp, err := http.NewRequest(http.MethodGet, GithubMemberURL.JoinPath(login).String(), nil)
	if err != nil {
		return false, fmt.Errorf("could not construct GitHub's user request: %w", err)
	}
	reqHttp.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	reqHttp.Header.Set("Accept", "application/vnd.github+json")

	resHttp, err := client.Do(reqHttp)
	if err != nil {
		return false, fmt.Errorf("could not send GitHub's user request: %w", err)
	}
	var githubRes GithubMemberUserResponse
	err = json.NewDecoder(resHttp.Body).Decode(&githubRes)
	if err != nil {
		return false, fmt.Errorf("could not parse GitHub's response: %w", err)
	}

	err = resHttp.Body.Close()
	if err != nil {
		return false, fmt.Errorf("could not close body: %w", err)
	}

	return githubRes.Role == ADMIN_ROLE, nil
}
