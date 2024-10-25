package main

import (
	"net/http"

	"github.com/kataras/muxie"
	"golang.org/x/exp/slog"

	"github.com/cartabinaria/auth/pkg/httputil"
	"github.com/cartabinaria/auth/pkg/middleware"
)

// NOTE: This is just a test binary, to test using the service as a centralized
// authorization middleware for other pieces of software.

func main() {
	mux := muxie.NewMux()
	mid, err := middleware.NewAuthMiddleware("http://localhost:3000")
	if err != nil {
		panic(err)
	}
	mux.Use(mid.Handler)

	// authentication api
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := middleware.GetUser(r)
		httputil.WriteData(w, http.StatusOK, u)
	})

	slog.Info("listening at", "address", ":3001")
	err = http.ListenAndServe(":3001", mux)
	if err != nil {
		slog.Error("failed to serve", "err", err)
	}
}
