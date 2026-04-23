package app

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rochael/RocNav/internal/models"
)

type mobileShortcutCatalogTestResponse struct {
	Categories []struct {
		ID        uint   `json:"id"`
		Name      string `json:"name"`
		SortOrder int    `json:"sort_order"`
	} `json:"categories"`
	Links []struct {
		ID         uint   `json:"id"`
		CategoryID uint   `json:"category_id"`
		Title      string `json:"title"`
		URL        string `json:"url"`
		IconURL    string `json:"icon_url"`
		IsPublic   bool   `json:"is_public"`
		SortOrder  int    `json:"sort_order"`
	} `json:"links"`
}

type mobileShortcutsTestResponse struct {
	LinkIDs   []uint     `json:"link_ids"`
	UpdatedAt *time.Time `json:"updated_at"`
}

func TestMobileShortcutCatalogReturnsSystemCategoriesAndLinks(t *testing.T) {
	app := newTestApp(t)

	systemOwner := zeroOwnerID
	categoryA := models.Category{Name: "Video", SortOrder: 1, OwnerID: &systemOwner}
	categoryB := models.Category{Name: "Social", SortOrder: 2, OwnerID: &systemOwner}
	privateOwner := uint(99)
	userCategory := models.Category{Name: "Hidden", SortOrder: 1, OwnerID: &privateOwner}
	if err := app.DB.Create(&[]models.Category{categoryA, categoryB, userCategory}).Error; err != nil {
		t.Fatalf("seed categories: %v", err)
	}

	systemLinks := []models.Link{
		{CategoryID: categoryA.ID, Title: "YouTube", URL: "https://youtube.com", IconURL: "https://cdn.example/youtube.png", IsPublic: true, SortOrder: 1, OwnerID: &systemOwner},
		{CategoryID: categoryB.ID, Title: "X", URL: "https://x.com", IconURL: "", IsPublic: false, SortOrder: 2, OwnerID: &systemOwner},
	}
	userLink := models.Link{CategoryID: userCategory.ID, Title: "Private", URL: "https://private.example", SortOrder: 1, OwnerID: &privateOwner}
	if err := app.DB.Create(&systemLinks).Error; err != nil {
		t.Fatalf("seed system links: %v", err)
	}
	if err := app.DB.Create(&userLink).Error; err != nil {
		t.Fatalf("seed user link: %v", err)
	}

	resp := performJSONRequest(t, app.Router, http.MethodGet, "/api/mobile/shortcut-catalog", nil, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected shortcut catalog 200, got %d: %s", resp.Code, resp.Body.String())
	}

	payload := decodeJSONResponse[mobileShortcutCatalogTestResponse](t, resp)
	if len(payload.Categories) != 2 {
		t.Fatalf("expected 2 system categories, got %d", len(payload.Categories))
	}
	if len(payload.Links) != 2 {
		t.Fatalf("expected 2 system links, got %d", len(payload.Links))
	}
	if payload.Links[0].Title != "YouTube" || payload.Links[1].Title != "X" {
		t.Fatalf("unexpected catalog order: %+v", payload.Links)
	}
}

func TestMobileShortcutsAnonymousReturnsEmptySelection(t *testing.T) {
	app := newTestApp(t)

	resp := performJSONRequest(t, app.Router, http.MethodGet, "/api/mobile/shortcuts", nil, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected anonymous mobile shortcuts 200, got %d: %s", resp.Code, resp.Body.String())
	}

	payload := decodeJSONResponse[mobileShortcutsTestResponse](t, resp)
	if len(payload.LinkIDs) != 0 {
		t.Fatalf("expected empty anonymous selection, got %+v", payload.LinkIDs)
	}
	if payload.UpdatedAt != nil {
		t.Fatalf("expected nil updated_at for anonymous response")
	}
}

func TestMobileShortcutsAuthenticatedParsesPersistedSelection(t *testing.T) {
	app := newTestApp(t)

	systemOwner := zeroOwnerID
	category := models.Category{Name: "System", SortOrder: 0, OwnerID: &systemOwner}
	if err := app.DB.Create(&category).Error; err != nil {
		t.Fatalf("seed category: %v", err)
	}
	links := []models.Link{
		{CategoryID: category.ID, Title: "A", URL: "https://a.example", IsPublic: true, SortOrder: 0, OwnerID: &systemOwner},
		{CategoryID: category.ID, Title: "B", URL: "https://b.example", IsPublic: true, SortOrder: 1, OwnerID: &systemOwner},
	}
	if err := app.DB.Create(&links).Error; err != nil {
		t.Fatalf("seed links: %v", err)
	}

	registerResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/auth/register", map[string]any{
		"email":    "mobile-shortcuts@example.com",
		"password": "password123",
		"nickname": "Mobile",
	}, "")
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register 200, got %d: %s", registerResp.Code, registerResp.Body.String())
	}
	registerPayload := decodeJSONResponse[authSessionTestResponse](t, registerResp)
	if err := app.DB.Model(&models.Shortcut{}).Where("owner_id = ?", registerPayload.User.ID).Update("links", joinShortcutLinkIDs([]uint{999, links[1].ID, links[0].ID, links[1].ID})).Error; err != nil {
		t.Fatalf("seed shortcut selection: %v", err)
	}

	resp := performJSONRequest(t, app.Router, http.MethodGet, "/api/mobile/shortcuts", nil, registerPayload.Token)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected authenticated mobile shortcuts 200, got %d: %s", resp.Code, resp.Body.String())
	}

	payload := decodeJSONResponse[mobileShortcutsTestResponse](t, resp)
	if len(payload.LinkIDs) != 2 || payload.LinkIDs[0] != links[1].ID || payload.LinkIDs[1] != links[0].ID {
		t.Fatalf("expected filtered preserved order [linkB, linkA], got %+v", payload.LinkIDs)
	}
	if payload.UpdatedAt == nil {
		t.Fatalf("expected updated_at for persisted selection")
	}
}

func TestMobileShortcutsUpdateFiltersInvalidIDsAndPreservesOrder(t *testing.T) {
	app := newTestApp(t)

	systemOwner := zeroOwnerID
	category := models.Category{Name: "System", SortOrder: 0, OwnerID: &systemOwner}
	if err := app.DB.Create(&category).Error; err != nil {
		t.Fatalf("seed category: %v", err)
	}
	links := []models.Link{
		{CategoryID: category.ID, Title: "A", URL: "https://a.example", SortOrder: 0, OwnerID: &systemOwner},
		{CategoryID: category.ID, Title: "B", URL: "https://b.example", SortOrder: 1, OwnerID: &systemOwner},
	}
	privateOwner := uint(777)
	privateCategory := models.Category{Name: "Private", SortOrder: 1, OwnerID: &privateOwner}
	if err := app.DB.Create(&privateCategory).Error; err != nil {
		t.Fatalf("seed private category: %v", err)
	}
	privateLink := models.Link{CategoryID: privateCategory.ID, Title: "Private", URL: "https://private.example", SortOrder: 0, OwnerID: &privateOwner}
	if err := app.DB.Create(&links).Error; err != nil {
		t.Fatalf("seed links: %v", err)
	}
	if err := app.DB.Create(&privateLink).Error; err != nil {
		t.Fatalf("seed private link: %v", err)
	}

	registerResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/auth/register", map[string]any{
		"email":    "mobile-shortcuts-update@example.com",
		"password": "password123",
		"nickname": "Updater",
	}, "")
	if registerResp.Code != http.StatusOK {
		t.Fatalf("expected register 200, got %d: %s", registerResp.Code, registerResp.Body.String())
	}
	registerPayload := decodeJSONResponse[authSessionTestResponse](t, registerResp)

	otp, err := totp.GenerateCode(registerPayload.TOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("generate otp: %v", err)
	}
	loginResp := performJSONRequest(t, app.Router, http.MethodPost, "/api/auth/login", map[string]any{
		"email":    "mobile-shortcuts-update@example.com",
		"password": "password123",
		"otp":      otp,
	}, "")
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}
	loginPayload := decodeJSONResponse[authSessionTestResponse](t, loginResp)

	updateResp := performJSONRequest(t, app.Router, http.MethodPut, "/api/mobile/shortcuts", map[string]any{
		"link_ids": []uint{privateLink.ID, 9999, links[1].ID, links[0].ID, links[1].ID},
	}, loginPayload.Token)
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected shortcut update 200, got %d: %s", updateResp.Code, updateResp.Body.String())
	}

	payload := decodeJSONResponse[mobileShortcutsTestResponse](t, updateResp)
	expected := []uint{links[1].ID, links[0].ID}
	if len(payload.LinkIDs) != len(expected) {
		t.Fatalf("expected %d link ids, got %+v", len(expected), payload.LinkIDs)
	}
	for index, id := range expected {
		if payload.LinkIDs[index] != id {
			t.Fatalf("expected preserved order %v, got %+v", expected, payload.LinkIDs)
		}
	}

	var shortcut models.Shortcut
	if err := app.DB.Where("owner_id = ?", registerPayload.User.ID).First(&shortcut).Error; err != nil {
		t.Fatalf("load persisted shortcut: %v", err)
	}
	expectedStored := joinShortcutLinkIDs(expected)
	if shortcut.Links != expectedStored {
		t.Fatalf("expected stored links %q, got %q", expectedStored, shortcut.Links)
	}
}
