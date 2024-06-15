package httputil

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

type ApiError struct {
	Msg string `json:"error"`
}

func WriteError(w http.ResponseWriter, status int, err string) {
	if eerr := writeJson(w, status, ApiError{Msg: err}); eerr != nil {
		slog.Error("could not write error to body", "err", eerr)
	}
}

func WriteData(w http.ResponseWriter, status int, data any) {
	if err := writeJson(w, status, data); err != nil {
		slog.Error("could not write data to body", "err", err)
	}
}

// WriteJson writes the specified body as JSON.
// The body is NOT CLOSED after writing to it.
//
// Returns an error if the write fails.
func writeJson(res http.ResponseWriter, status int, body any) error {
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(status)

	err := json.NewEncoder(res).Encode(body)
	if err != nil {
		return fmt.Errorf("could not encode json: %w", err)
	}

	return nil
}
