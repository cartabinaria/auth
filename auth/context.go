package auth

import (
	"github.com/csunibo/auth"
	"net/http"
)

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
