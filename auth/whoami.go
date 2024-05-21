package auth

import (
	"log/slog"
	"net/http"

	"github.com/csunibo/cs-git-login/util"
)

func WhoAmIHandler(res http.ResponseWriter, req *http.Request) {
	user := GetUser(req)
	if err := util.WriteJson(res, user); err != nil {
		_ = util.WriteError(res, http.StatusInternalServerError, "")
		slog.Error("could not encode json:", "error", err)
	}
}
