package auth

import (
	"log/slog"
	"net/http"

	"github.com/csunibo/cs-git-login/util"
)

// @Summary			Who am I
// @Description		Return user information if logged in
// @Tags			login
// @Produce			json
// @Success			200	{object}	User
// @Failure			400	{object}	string
// @Router			/whoami [get]
func WhoAmIHandler(res http.ResponseWriter, req *http.Request) {
	user := GetUser(req)
	if err := util.WriteJson(res, user); err != nil {
		_ = util.WriteError(res, http.StatusInternalServerError, "")
		slog.Error("could not encode json:", "error", err)
	}
}
