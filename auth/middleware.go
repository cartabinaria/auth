package auth

import (
	"context"
	"net/http"

	"github.com/csunibo/cs-git-login/util"
	"github.com/golang-jwt/jwt/v5"
)

func (a *Authenticator) RequireJWTCookie(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		_ = util.WriteError(w, http.StatusUnauthorized, "you are not logged in")
		return nil, err
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return a.signingKey, nil
	}

	parsedToken, err := jwt.Parse(cookie.Value, keyFunc)
	if err != nil {
		_ = util.WriteError(w, http.StatusUnauthorized, "invalid token")
		return nil, err
	}

	return parsedToken, nil
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodOptions {
			next.ServeHTTP(res, req)
		} else {
			parsedToken, err := a.RequireJWTCookie(res, req)
			if err != nil {
				return
			}

			userMap, ok := parsedToken.Claims.(jwt.MapClaims)["user"].(map[string]interface{})
			if !ok {
				_ = util.WriteError(res, http.StatusUnauthorized, "could not read JWT contents")
				return
			}
			user := User{
				Username:  userMap["username"].(string),
				AvatarUrl: userMap["avatarUrl"].(string),
				Name:      userMap["name"].(string),
				Email:     userMap["email"].(string),
				Admin:     userMap["admin"].(bool),
			}
			ctx := context.WithValue(req.Context(), AuthContextKey, user)

			next.ServeHTTP(res, req.WithContext(ctx))
		}
	})
}
