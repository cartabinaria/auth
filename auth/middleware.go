package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cartabinaria/auth"
	"github.com/cartabinaria/auth/pkg/httputil"
	"github.com/golang-jwt/jwt/v5"
)

func (a *Authenticator) ParseJWTCookie(cookie string, w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		return a.signingKey, nil
	}

	parsedToken, err := jwt.Parse(cookie, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %v", err)
	}

	return parsedToken, nil
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
		} else {
			cookie, err := r.Cookie("auth")
			if err != nil {
				httputil.WriteError(w, http.StatusUnauthorized, "you are not logged in")
				return
			}
			parsedToken, err := a.ParseJWTCookie(cookie.Value, w, r)
			if err != nil {
				httputil.WriteError(w, http.StatusUnauthorized, "invalid JWT token")
				return
			}

			userMap, ok := parsedToken.Claims.(jwt.MapClaims)["user"].(map[string]any)
			if !ok {
				httputil.WriteError(w, http.StatusUnauthorized, "could not read JWT contents")
				return
			}
			user := auth.User{
				Username:  userMap["username"].(string),
				ID:        uint(userMap["id"].(float64)),
				AvatarUrl: userMap["avatarUrl"].(string),
				Name:      userMap["name"].(string),
				Email:     userMap["email"].(string),
				Role:      auth.Role(userMap["role"].(string)),
			}
			ctx := context.WithValue(r.Context(), AuthContextKey, user)

			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
