package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rochael/RocNav/internal/config"
)

type authSessionTestResponse struct {
	User struct {
		ID    uint   `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Token      string `json:"token"`
	TOTPSecret string `json:"totp_secret"`
	TOTPURL    string `json:"totp_url"`
}

type bookmarkSyncTestResponse struct {
	Bookmarks []struct {
		ID         uint       `json:"id"`
		ClientUUID string     `json:"client_uuid"`
		Title      string     `json:"title"`
		URL        string     `json:"url"`
		GroupName  string     `json:"group_name"`
		SortOrder  int        `json:"sort_order"`
		IsDeleted  bool       `json:"is_deleted"`
		DeletedAt  *time.Time `json:"deleted_at"`
		CreatedAt  time.Time  `json:"created_at"`
		UpdatedAt  time.Time  `json:"updated_at"`
	} `json:"bookmarks"`
	ServerTime string `json:"server_time"`
}

type authMeTestResponse struct {
	User               any  `json:"user"`
	AllowRegister      bool `json:"allow_register"`
	GitHubOAuthEnabled bool `json:"github_oauth_enabled"`
	GoogleOAuthEnabled bool `json:"google_oauth_enabled"`
}

func newTestApp(t *testing.T) *App {
	t.Helper()

	cfg := &config.Config{
		Addr:           ":0",
		DBPath:         filepath.Join(t.TempDir(), "rocnav-test.db"),
		JWTSecret:      []byte("0123456789abcdef0123456789abcdef"),
		JWTIssuer:      "rocnav-test",
		JWTTTL:         24 * time.Hour,
		FrontendOrigin: "http://localhost:5173",
		GitHubRedirect: "http://localhost:8080/api/auth/github/callback",
		AllowRegister:  true,
	}
	return NewWithConfig(cfg)
}

func performJSONRequest(t *testing.T, router http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		reader = bytes.NewReader(payload)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func decodeJSONResponse[T any](t *testing.T, resp *httptest.ResponseRecorder) T {
	t.Helper()

	var payload T
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v\nbody=%s", err, resp.Body.String())
	}
	return payload
}

func TestAuthEndpointsReturnMobileFields(t *testing.T) {
	app := newTestApp(t)

	meResp := performJSONRequest(t, app.Router, http.MethodGet, "/api/auth/me", nil, "")
	if meResp.Code != http.StatusOK {
		t.Fatalf("expected /api/auth/me 200, got %d: %s", meResp.Code, meResp.Body.String())
	}
	mePayload := decodeJSONResponse[authMeTestResponse](t, meResp)
	if mePayload.User != nil {
		t.Fatalf("expected anonymous /api/auth/me to return nil user")
	}
	if !mePayload.AllowRegister {
		t.Fatalf("expected allow_register to be true")
	}
	if mePayload.GitHubOAuthEnabled {
		t.Fatalf("expected github_oauth_enabled to be false in test config")
	}
	if mePayload.GoogleOAuthEnabled {
		t.Fatalf("expected google_oauth_enabled to be false in test config")
	}

	registerResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/auth/register", map[string]any{
		"email":    "sync@example.com",
		"password": "password123",
		"nickname": "Sync User",
	}, "")
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register 200, got %d: %s", registerResp.Code, registerResp.Body.String())
	}
	registerPayload := decodeJSONResponse[authSessionTestResponse](t, registerResp)
	if registerPayload.Token == "" {
		t.Fatalf("expected register response token")
	}
	if registerPayload.TOTPSecret == "" || registerPayload.TOTPURL == "" {
		t.Fatalf("expected register response to include TOTP bootstrap data")
	}

	otp, err := totp.GenerateCode(registerPayload.TOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("generate otp: %v", err)
	}

	loginResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/auth/login", map[string]any{
		"email":    "sync@example.com",
		"password": "password123",
		"otp":      otp,
	}, "")
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}
	loginPayload := decodeJSONResponse[authSessionTestResponse](t, loginResp)
	if loginPayload.Token == "" {
		t.Fatalf("expected login response token")
	}

	authedMeResp := performJSONRequest(t, app.Router, http.MethodGet, "/api/auth/me", nil, loginPayload.Token)
	if authedMeResp.Code != http.StatusOK {
		t.Fatalf("expected authenticated /api/auth/me 200, got %d: %s", authedMeResp.Code, authedMeResp.Body.String())
	}
	authedMePayload := decodeJSONResponse[authMeTestResponse](t, authedMeResp)
	if authedMePayload.User == nil {
		t.Fatalf("expected authenticated /api/auth/me to return a user")
	}
}

func TestBookmarkSyncLastWriteWinsAndTombstones(t *testing.T) {
	app := newTestApp(t)

	registerResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/auth/register", map[string]any{
		"email":    "bookmarks@example.com",
		"password": "password123",
		"nickname": "Bookmarks",
	}, "")
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register 200, got %d: %s", registerResp.Code, registerResp.Body.String())
	}
	registerPayload := decodeJSONResponse[authSessionTestResponse](t, registerResp)

	createdAt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	initialUpdatedAt := createdAt.Add(2 * time.Minute)
	syncResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/bookmarks/sync", map[string]any{
		"changes": []map[string]any{
			{
				"client_uuid": "local-bookmark-1",
				"title":       "Initial title",
				"url":         "https://example.com/a",
				"group_name":  "Favorites",
				"sort_order":  0,
				"is_deleted":  false,
				"created_at":  createdAt.Format(time.RFC3339Nano),
				"updated_at":  initialUpdatedAt.Format(time.RFC3339Nano),
			},
		},
	}, registerPayload.Token)
	if syncResp.Code != http.StatusOK {
		t.Fatalf("expected initial sync 200, got %d: %s", syncResp.Code, syncResp.Body.String())
	}
	syncPayload := decodeJSONResponse[bookmarkSyncTestResponse](t, syncResp)
	if len(syncPayload.Bookmarks) != 1 {
		t.Fatalf("expected 1 bookmark after initial sync, got %d", len(syncPayload.Bookmarks))
	}
	bookmarkID := syncPayload.Bookmarks[0].ID

	since := createdAt.Add(-time.Minute).Format(time.RFC3339Nano)
	deltaResp := performJSONRequest(t, app.Router, http.MethodGet, "/api/bookmarks/sync?since="+since+"&include_deleted=1", nil, registerPayload.Token)
	if deltaResp.Code != http.StatusOK {
		t.Fatalf("expected delta sync 200, got %d: %s", deltaResp.Code, deltaResp.Body.String())
	}
	deltaPayload := decodeJSONResponse[bookmarkSyncTestResponse](t, deltaResp)
	if len(deltaPayload.Bookmarks) != 1 {
		t.Fatalf("expected delta sync to return 1 bookmark, got %d", len(deltaPayload.Bookmarks))
	}

	olderUpdate := performJSONRequest(t, app.Router, http.MethodPost, "/api/bookmarks/sync", map[string]any{
		"changes": []map[string]any{
			{
				"id":          bookmarkID,
				"client_uuid": "local-bookmark-1",
				"title":       "Older title should lose",
				"url":         "https://example.com/a",
				"group_name":  "Favorites",
				"sort_order":  0,
				"is_deleted":  false,
				"created_at":  createdAt.Format(time.RFC3339Nano),
				"updated_at":  createdAt.Add(time.Minute).Format(time.RFC3339Nano),
			},
		},
	}, registerPayload.Token)
	if olderUpdate.Code != http.StatusOK {
		t.Fatalf("expected older update sync 200, got %d: %s", olderUpdate.Code, olderUpdate.Body.String())
	}
	olderPayload := decodeJSONResponse[bookmarkSyncTestResponse](t, olderUpdate)
	if got := olderPayload.Bookmarks[0].Title; got != "Initial title" {
		t.Fatalf("expected newer server version to win, got %q", got)
	}

	deletedAt := createdAt.Add(5 * time.Minute)
	deleteResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/bookmarks/sync", map[string]any{
		"changes": []map[string]any{
			{
				"id":          bookmarkID,
				"client_uuid": "local-bookmark-1",
				"title":       "Initial title",
				"url":         "https://example.com/a",
				"group_name":  "Favorites",
				"sort_order":  0,
				"is_deleted":  true,
				"deleted_at":  deletedAt.Format(time.RFC3339Nano),
				"created_at":  createdAt.Format(time.RFC3339Nano),
				"updated_at":  deletedAt.Format(time.RFC3339Nano),
			},
		},
	}, registerPayload.Token)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected delete sync 200, got %d: %s", deleteResp.Code, deleteResp.Body.String())
	}
	deletePayload := decodeJSONResponse[bookmarkSyncTestResponse](t, deleteResp)
	if len(deletePayload.Bookmarks) != 1 || !deletePayload.Bookmarks[0].IsDeleted {
		t.Fatalf("expected deleted bookmark tombstone in authoritative sync response")
	}

	visibleResp := performJSONRequest(t, app.Router, http.MethodGet, "/api/bookmarks/sync", nil, registerPayload.Token)
	if visibleResp.Code != http.StatusOK {
		t.Fatalf("expected visible sync 200, got %d: %s", visibleResp.Code, visibleResp.Body.String())
	}
	visiblePayload := decodeJSONResponse[bookmarkSyncTestResponse](t, visibleResp)
	if len(visiblePayload.Bookmarks) != 0 {
		t.Fatalf("expected deleted bookmarks to be excluded by default, got %d", len(visiblePayload.Bookmarks))
	}

	tombstoneResp := performJSONRequest(t, app.Router, http.MethodGet, "/api/bookmarks/sync?include_deleted=1", nil, registerPayload.Token)
	if tombstoneResp.Code != http.StatusOK {
		t.Fatalf("expected tombstone sync 200, got %d: %s", tombstoneResp.Code, tombstoneResp.Body.String())
	}
	tombstonePayload := decodeJSONResponse[bookmarkSyncTestResponse](t, tombstoneResp)
	if len(tombstonePayload.Bookmarks) != 1 || !tombstonePayload.Bookmarks[0].IsDeleted {
		t.Fatalf("expected tombstone to remain available when include_deleted=1")
	}
}
