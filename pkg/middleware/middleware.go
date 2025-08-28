package middleware

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/cartabinaria/auth"
	"github.com/cartabinaria/auth/pkg/httputil"
)

type AuthMiddleware struct {
	authServer *url.URL
}

const WhoamiEndpoint = "whoami"
const AuthContextKey = "auth"

func GetUser(req *http.Request) auth.User {
	user, ok := req.Context().Value(AuthContextKey).(auth.User)
	if !ok {
		panic("Could not get the User out of the context")
	}
	return user
}

func GetAdmin(req *http.Request) bool {
	user := GetUser(req)
	return user.Admin
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
		cookie, err := r.Cookie("auth")
		if err != nil {
			httputil.WriteError(w, http.StatusUnauthorized, "you are not logged in")
			return
		}

		jar, err := cookiejar.New(nil)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "could not check log-in status")
			slog.Error("error while creating cookie jar (for authentication)", "err", err)
			return
		}
		slog.Debug("forwarding cookie to auth service", "cookie", cookie.String())
		jar.SetCookies(a.authServer, []*http.Cookie{cookie})

		client := &http.Client{
			Jar: jar,
		}
		req, err := http.NewRequest(http.MethodGet, a.authServer.JoinPath(WhoamiEndpoint).String(), nil)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "could not check log-in status")
			slog.Error("error while creating the request to auth server", "err", err)
			return
		}
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		var (
			user   auth.User
			apiErr httputil.ApiError
		)

		bodyBytes, err := io.ReadAll(res.Body)

		err = json.Unmarshal(bodyBytes, &user)
		if err != nil {
			err = json.Unmarshal(bodyBytes, &apiErr)
			if err != nil {
				httputil.WriteError(w, http.StatusUnauthorized, "you are not logged in")
				slog.Error("auth server returned unexpected response", "err", err)
				return
			}
			httputil.WriteError(w, http.StatusUnauthorized, apiErr.Msg)
			return
		}

		ctx := context.WithValue(r.Context(), AuthContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
