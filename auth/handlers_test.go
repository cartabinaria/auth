package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
)

// All identities, credentials, and responses below are synthetic fixtures.
// This transport has no network fallback.
type githubFixtureTransport struct {
	t              *testing.T
	calls          int
	failAt         int
	transportError bool
}

func (f *githubFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	methods := []string{http.MethodPost, http.MethodGet, http.MethodGet}
	endpoints := []string{
		GithubAccessTokenURL.String(),
		GithubUserURL.String(),
		GithubMemberURL.JoinPath("fixture-user").String(),
	}
	bodies := []string{
		`{"access_token":"fixture-access-token","token_type":"bearer"}`,
		`{"id":424242,"name":"Fixture User","login":"fixture-user","email":"fixture-user@example.invalid","avatar_url":"https://example.invalid/fixture-avatar","url":"https://example.invalid/fixture-user"}`,
		`{"role":"member"}`,
	}
	if f.calls > len(endpoints) || req.Method != methods[f.calls-1] || req.URL.String() != endpoints[f.calls-1] {
		f.t.Error("unexpected request to fixture transport")
		return nil, errors.New("unexpected fixture request")
	}
	if f.calls == f.failAt && f.transportError {
		return nil, errors.New("fixture transport failure")
	}
	body := bodies[f.calls-1]
	if f.calls == f.failAt {
		body = "fixture-invalid-json"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func captureSessionLogs(t *testing.T, res *httptest.ResponseRecorder) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(writer)
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	})
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key != slog.MessageKey {
				return attr
			}
			message := attr.Value.String()
			if message != "session created" && message != "session cookie cleared" {
				return attr
			}
			response := &http.Response{Header: res.Header()}
			for _, cookie := range response.Cookies() {
				if cookie.Name == "auth" {
					if (message == "session created") != (cookie.Value != "") {
						t.Error("session event does not match the auth cookie")
					}
					return attr
				}
			}
			t.Error("session event emitted before setting the auth cookie")
			return attr
		},
	})))
	return &logs
}

func checkSessionEvent(t *testing.T, logs *bytes.Buffer, want string) {
	t.Helper()
	decoder := json.NewDecoder(logs)
	count := 0
	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		record := make(map[string]any)
		fields := 0
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			record[key.(string)] = value
			fields++
		}
		if _, err := decoder.Token(); err != nil {
			t.Fatal(err)
		}
		if record["level"] != "INFO" && record["msg"] != "session created" && record["msg"] != "session cookie cleared" {
			continue
		}
		count++
		if want == "" || record["msg"] != want || record["level"] != "INFO" {
			t.Error("unexpected session event")
		}
		if fields != 3 || len(record) != 3 || record["time"] == nil {
			t.Error("session event must contain only time, level, and a fixed message")
		}
	}
	if want != "" && count != 1 {
		t.Errorf("got %d session events, want one %q", count, want)
	}
}

func TestCallbackSessionEvent(t *testing.T) {
	for _, tc := range []struct {
		name           string
		field          string
		value          string
		noStateCookie  bool
		failAt         int
		transportError bool
		signingError   bool
		wantStatus     int
		wantCalls      int
		wantEvent      string
	}{
		{name: "success", wantStatus: http.StatusSeeOther, wantCalls: 3, wantEvent: "session created"},
		{name: "missing state cookie", noStateCookie: true, wantStatus: http.StatusBadRequest},
		{name: "invalid state", field: "state", value: "fixture-wrong-state", wantStatus: http.StatusBadRequest},
		{name: "oauth error", field: "error", value: "fixture-oauth-error", wantStatus: http.StatusInternalServerError},
		{name: "missing code", field: "code", wantStatus: http.StatusBadRequest},
		{name: "missing redirect", field: "redirect_uri", wantStatus: http.StatusBadRequest},
		{name: "invalid redirect", field: "redirect_uri", value: "%fixture-invalid-uri", wantStatus: http.StatusBadRequest},
		{name: "token transport error", failAt: 1, transportError: true, wantStatus: http.StatusBadRequest, wantCalls: 1},
		{name: "token decode error", failAt: 1, wantStatus: http.StatusBadRequest, wantCalls: 1},
		{name: "user transport error", failAt: 2, transportError: true, wantStatus: http.StatusInternalServerError, wantCalls: 2},
		{name: "user decode error", failAt: 2, wantStatus: http.StatusInternalServerError, wantCalls: 2},
		{name: "membership decode error", failAt: 3, wantStatus: http.StatusInternalServerError, wantCalls: 3},
		{name: "signing error", signingError: true, wantStatus: http.StatusInternalServerError, wantCalls: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &githubFixtureTransport{t: t, failAt: tc.failAt, transportError: tc.transportError}
			previousClient := client
			client = &http.Client{Transport: transport}
			t.Cleanup(func() { client = previousClient })
			if tc.signingError {
				previousMethod := jwt.SigningMethodHS256
				// An unavailable hash exercises SignedString's error without changing production code.
				jwt.SigningMethodHS256 = &jwt.SigningMethodHMAC{Name: "HS256", Hash: 0}
				t.Cleanup(func() { jwt.SigningMethodHS256 = previousMethod })
			}
			a := NewAuthenticator(&Config{
				ClientID:     "fixture-client-id",
				ClientSecret: "fixture-client-secret",
				SigningKey:   []byte("fixture-signing-key-not-for-production"),
				Expiration:   time.Hour,
				CookieDomain: "example.invalid",
			})
			query := url.Values{
				"state":        {"fixture-state"},
				"code":         {"fixture-code"},
				"redirect_uri": {"https://client.example.invalid/fixture-return?email=fixture-user%40example.invalid"},
			}
			if tc.field != "" {
				query.Set(tc.field, tc.value)
			}
			req := httptest.NewRequest(http.MethodGet, "https://auth.example.invalid/login/callback?"+query.Encode(), nil)
			req.RemoteAddr = "192.0.2.1:12345"
			req.Header.Set("Authorization", "fixture-authorization")
			if !tc.noStateCookie {
				req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "fixture-state"})
			}
			res := httptest.NewRecorder()
			logs := captureSessionLogs(t, res)
			a.CallbackHandler(res, req)

			if res.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", res.Code, tc.wantStatus)
			}
			if transport.calls != tc.wantCalls {
				t.Errorf("fixture requests = %d, want %d", transport.calls, tc.wantCalls)
			}
			checkSessionEvent(t, logs, tc.wantEvent)
			var session *http.Cookie
			for _, cookie := range res.Result().Cookies() {
				if cookie.Name == "auth" {
					session = cookie
				}
			}
			if tc.wantEvent == "" {
				if session != nil || res.Header().Get("Location") != "" {
					t.Error("failed callback issued a session or redirect")
				}
				return
			}
			if session == nil || session.Value == "" {
				t.Fatal("successful callback did not set a session cookie")
			}
			if !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteNoneMode || session.Path != "/" || session.Domain != "example.invalid" || !session.Expires.After(time.Now()) {
				t.Error("session cookie attributes changed")
			}
			redirect, err := url.Parse(res.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if redirect.Scheme != "https" || redirect.Host != "client.example.invalid" || redirect.Path != "/fixture-return" || redirect.Query().Get("email") != "fixture-user@example.invalid" || redirect.Query().Get("session_token") != session.Value {
				t.Error("callback redirect changed")
			}
			token, err := jwt.Parse(session.Value, func(_ *jwt.Token) (any, error) {
				return a.signingKey, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			claims := token.Claims.(jwt.MapClaims)
			if claims["id"] != float64(424242) || claims["token"] != "fixture-access-token" {
				t.Error("signed session claims changed")
			}
		})
	}
}

func TestLogoutSessionEvent(t *testing.T) {
	key := []byte("fixture-signing-key-not-for-production")
	user := map[string]any{
		"id": 424242, "username": "fixture-user", "name": "Fixture User",
		"email": "fixture-user@example.invalid", "avatarUrl": "https://example.invalid/fixture-avatar", "role": "member",
	}
	validToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(), "id": 424242, "token": "fixture-access-token", "user": user,
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(-time.Hour).Unix(), "id": 424242, "token": "fixture-access-token", "user": user,
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		cookie        string
		authorization string
		noRedirect    bool
		wantStatus    int
		wantEvent     string
	}{
		{name: "anonymous", wantStatus: http.StatusSeeOther, wantEvent: "session cookie cleared"},
		{name: "malformed cookie", cookie: "fixture-not-a-jwt", wantStatus: http.StatusSeeOther, wantEvent: "session cookie cleared"},
		{name: "expired cookie", cookie: expiredToken, wantStatus: http.StatusSeeOther, wantEvent: "session cookie cleared"},
		{name: "valid cookie", cookie: validToken, wantStatus: http.StatusSeeOther, wantEvent: "session cookie cleared"},
		{name: "authorization only", authorization: "fixture-authorization", wantStatus: http.StatusSeeOther, wantEvent: "session cookie cleared"},
		{name: "missing redirect", cookie: validToken, noRedirect: true, wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &githubFixtureTransport{t: t}
			previousClient := client
			client = &http.Client{Transport: transport}
			t.Cleanup(func() { client = previousClient })
			a := NewAuthenticator(&Config{SigningKey: key, CookieDomain: "example.invalid"})
			redirect := "https://client.example.invalid/fixture-return?email=fixture-user%40example.invalid"
			query := url.Values{}
			if !tc.noRedirect {
				query.Set("redirect_uri", redirect)
			}
			req := httptest.NewRequest(http.MethodGet, "https://auth.example.invalid/logout?"+query.Encode(), nil)
			req.RemoteAddr = "192.0.2.1:12345"
			req.Header.Set("Authorization", tc.authorization)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "auth", Value: tc.cookie})
			}
			res := httptest.NewRecorder()
			logs := captureSessionLogs(t, res)
			a.LogoutHandler(res, req)

			if res.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", res.Code, tc.wantStatus)
			}
			if transport.calls != 0 {
				t.Error("logout contacted the OAuth fixture transport")
			}
			checkSessionEvent(t, logs, tc.wantEvent)
			cookies := res.Result().Cookies()
			if tc.noRedirect {
				if len(cookies) != 0 || res.Header().Get("Location") != "" {
					t.Error("failed logout changed cookies or redirected")
				}
				return
			}
			if len(cookies) != 1 {
				t.Fatal("logout did not set exactly one cookie")
			}
			cookie := cookies[0]
			if cookie.Name != "auth" || cookie.Value != "" || !cookie.Expires.Equal(time.Unix(0, 0)) || cookie.Domain != "example.invalid" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode {
				t.Error("logout cookie attributes changed")
			}
			if res.Header().Get("Location") != redirect {
				t.Error("logout redirect changed")
			}
		})
	}
}
