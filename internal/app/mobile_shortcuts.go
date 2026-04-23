package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
)

type mobileShortcutCatalogCategory struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	SortOrder int    `json:"sort_order"`
}

type mobileShortcutCatalogLink struct {
	ID         uint   `json:"id"`
	CategoryID uint   `json:"category_id"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	IconURL    string `json:"icon_url"`
	IsPublic   bool   `json:"is_public"`
	SortOrder  int    `json:"sort_order"`
}

type mobileShortcutsResponse struct {
	LinkIDs   []uint     `json:"link_ids"`
	UpdatedAt *time.Time `json:"updated_at"`
}

func (a *App) handleMobileShortcutCatalog(c *gin.Context) {
	var categories []models.Category
	var links []models.Link

	a.DB.Where("owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&categories)
	a.DB.Where("owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&links)

	categoryPayload := make([]mobileShortcutCatalogCategory, 0, len(categories))
	for _, category := range categories {
		categoryPayload = append(categoryPayload, mobileShortcutCatalogCategory{
			ID:        category.ID,
			Name:      category.Name,
			SortOrder: category.SortOrder,
		})
	}

	linkPayload := make([]mobileShortcutCatalogLink, 0, len(links))
	for _, link := range links {
		linkPayload = append(linkPayload, mobileShortcutCatalogLink{
			ID:         link.ID,
			CategoryID: link.CategoryID,
			Title:      link.Title,
			URL:        link.URL,
			IconURL:    link.IconURL,
			IsPublic:   link.IsPublic,
			SortOrder:  link.SortOrder,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"categories": categoryPayload,
		"links":      linkPayload,
	})
}

func (a *App) handleMobileShortcuts(c *gin.Context) {
	user, _ := a.currentUser(c)
	if user == nil {
		c.JSON(http.StatusOK, mobileShortcutsResponse{LinkIDs: []uint{}})
		return
	}

	shortcut, linkIDs := a.loadShortcutSelection(user.ID)
	response := mobileShortcutsResponse{LinkIDs: linkIDs}
	if shortcut != nil {
		response.UpdatedAt = &shortcut.UpdatedAt
	}
	c.JSON(http.StatusOK, response)
}

func (a *App) handleUpdateMobileShortcuts(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	var req struct {
		LinkIDs []uint `json:"link_ids"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	filteredLinkIDs := a.filterSystemShortcutLinkIDs(req.LinkIDs)
	serialized := joinShortcutLinkIDs(filteredLinkIDs)

	var shortcut models.Shortcut
	if err := a.DB.Where("owner_id = ?", user.ID).First(&shortcut).Error; err != nil {
		shortcut = models.Shortcut{OwnerID: user.ID, Links: serialized}
		if err := a.DB.Create(&shortcut).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
			return
		}
	} else {
		shortcut.Links = serialized
		if err := a.DB.Save(&shortcut).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
			return
		}
	}

	c.JSON(http.StatusOK, mobileShortcutsResponse{
		LinkIDs:   filteredLinkIDs,
		UpdatedAt: &shortcut.UpdatedAt,
	})
}

func (a *App) loadShortcutSelection(ownerID uint) (*models.Shortcut, []uint) {
	var shortcut models.Shortcut
	if err := a.DB.Where("owner_id = ?", ownerID).First(&shortcut).Error; err != nil {
		return nil, []uint{}
	}

	return &shortcut, a.filterSystemShortcutLinkIDs(parseShortcutLinks(shortcut.Links))
}

func (a *App) filterSystemShortcutLinkIDs(linkIDs []uint) []uint {
	if len(linkIDs) == 0 {
		return []uint{}
	}

	uniqueIDs := make([]uint, 0, len(linkIDs))
	seen := make(map[uint]struct{}, len(linkIDs))
	for _, linkID := range linkIDs {
		if linkID == 0 {
			continue
		}
		if _, exists := seen[linkID]; exists {
			continue
		}
		seen[linkID] = struct{}{}
		uniqueIDs = append(uniqueIDs, linkID)
	}

	var validIDs []uint
	a.DB.Model(&models.Link{}).
		Where("owner_id = ? AND id IN ?", zeroOwnerID, uniqueIDs).
		Order("sort_order asc, id asc").
		Pluck("id", &validIDs)

	if len(validIDs) == 0 {
		return []uint{}
	}

	validSet := make(map[uint]struct{}, len(validIDs))
	for _, id := range validIDs {
		validSet[id] = struct{}{}
	}

	filtered := make([]uint, 0, len(validIDs))
	for _, id := range uniqueIDs {
		if _, ok := validSet[id]; ok {
			filtered = append(filtered, id)
		}
	}
	return filtered
}

func parseShortcutLinks(raw string) []uint {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []uint{}
	}

	parts := strings.Split(raw, ",")
	ids := make([]uint, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || parsed == 0 {
			continue
		}
		ids = append(ids, uint(parsed))
	}
	return ids
}

func joinShortcutLinkIDs(linkIDs []uint) string {
	if len(linkIDs) == 0 {
		return ""
	}

	parts := make([]string, 0, len(linkIDs))
	for _, id := range linkIDs {
		parts = append(parts, strconv.FormatUint(uint64(id), 10))
	}
	return strings.Join(parts, ",")
}
