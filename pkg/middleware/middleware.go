package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/cartabinaria/auth"
	"github.com/cartabinaria/auth/pkg/httputil"
)

type AuthMiddleware struct {
	authServer *url.URL
}

const WhoamiEndpoint = "whoami"
const AuthContextKey = "auth"

func GetUser(req *http.Request) (auth.User, error) {
	user, ok := req.Context().Value(AuthContextKey).(auth.User)
	if !ok {
		return auth.User{}, fmt.Errorf("Could not get the User out of the context")
	}
	return user, nil
}

func MustGetUser(req *http.Request) auth.User {
	user, ok := req.Context().Value(AuthContextKey).(auth.User)
	if !ok {
		panic("Could not get the User out of the context")
	}
	return user
}

func GetAdmin(req *http.Request) bool {
	user, err := GetUser(req)
	if err != nil {
		return false
	}
	return user.Role == auth.RoleAdmin
}

func GetMember(req *http.Request) bool {
	user, err := GetUser(req)
	if err != nil {
		return false
	}
	return user.Role == auth.RoleMember
}

func NewAuthMiddleware(authServer string) (mid *AuthMiddleware, err error) {
	srv, err := url.Parse(authServer)
	if err != nil {
		return
	}

	mid = &AuthMiddleware{
		authServer: srv,
	}
	return
}

func (a *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		cookie, err := r.Cookie("auth")
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			httputil.WriteError(w, http.StatusUnauthorized, "you are not logged in")
			return
		} else if errors.Is(err, http.ErrNoCookie) {
			token = r.Header.Get("Authorization")
			if token == "" {
				httputil.WriteError(w, http.StatusUnauthorized, "you are not logged in")
				return
			}
		} else {
			token = cookie.Value
		}

		user, returnStatus, err := tryAuth(token, a.authServer.JoinPath(WhoamiEndpoint).String())
		if err != nil {
			slog.Error("error while trying to authenticate user", "err", err)
			httputil.WriteError(w, returnStatus, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), AuthContextKey, *user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *AuthMiddleware) NonBlockingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var token string

		cookie, err := r.Cookie("auth")
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			slog.Debug("Passing request to next handler without auth context")
			next.ServeHTTP(w, r)
			return
		} else if errors.Is(err, http.ErrNoCookie) {
			token = r.Header.Get("Authorization")
			if token == "" {
				slog.Debug("Passing request to next handler without auth context")
				next.ServeHTTP(w, r)
				return
			}
		} else {
			token = cookie.Value
		}

		user, returnStatus, err := tryAuth(token, a.authServer.JoinPath(WhoamiEndpoint).String())
		if err != nil {
			slog.Error("error while trying to authenticate user", "err", err)
			httputil.WriteError(w, returnStatus, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), AuthContextKey, *user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tryAuth(token, endpoint string) (*auth.User, int, error) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("could not construct auth server request: %w", err)
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	var (
		user   auth.User
		apiErr httputil.ApiError
	)

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("could not read auth server response: %w", err)
	}

	err = json.Unmarshal(bodyBytes, &apiErr)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("auth server returned unexpected response: %w", err)
	}

	if apiErr.Msg != "" {
		return nil, http.StatusInternalServerError, fmt.Errorf("auth server returned error: %s", apiErr.Msg)
	}

	err = json.Unmarshal(bodyBytes, &user)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("could not parse auth server response: %w", err)
	}

	if user.Username == "" {
		return nil, http.StatusUnauthorized, fmt.Errorf("auth server returned empty user")
	}

	return &user, http.StatusOK, nil
}
