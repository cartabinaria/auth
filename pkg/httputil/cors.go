package httputil

import (
	"net/http"
	"slices"

	"github.com/kataras/muxie"
)

func NewCorsMiddleware(origins []string, allowCredentials bool, handler http.Handler) muxie.Wrapper {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			if slices.Contains(origins, req.Header.Get("origin")) {
				res.Header().Set("Access-Control-Allow-Origin", req.Header.Get("origin"))
			}
			res.Header().Set("Access-Control-Allow-Credentials", "true")
			// allow pre-flight
			if req.Method == http.MethodOptions {
				res.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE")
				res.Header().Set("Access-Control-Allow-Headers", "Content-Type, Origin, Accept, token")
				res.WriteHeader(http.StatusOK)
			} else {
				next.ServeHTTP(res, req)
			}
		})
	}
}
