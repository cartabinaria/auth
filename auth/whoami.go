package auth

import (
	"net/http"

	"github.com/csunibo/auth/pkg/httputil"
)

// @Summary		Who am I
// @Description	Return user information if logged in
// @Tags			login
// @Produce		json
// @Success		200	{object}	User
// @Failure		400	{object}	string
// @Router			/whoami [get]
func WhoAmIHandler(res http.ResponseWriter, req *http.Request) {
	httputil.WriteData(res, http.StatusOK, GetUser(req))
}
