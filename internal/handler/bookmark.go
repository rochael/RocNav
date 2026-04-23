package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/service"
)

type BookmarkHandler struct {
	svc *service.BookmarkService
}

func NewBookmarkHandler(svc *service.BookmarkService) *BookmarkHandler {
	return &BookmarkHandler{svc: svc}
}

type bookmarkSyncItem struct {
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
}

func (h *BookmarkHandler) GetSync(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	since, _ := parseSyncSince(c.Query("since"))
	includeDeleted := c.Query("include_deleted") == "1" || strings.EqualFold(c.Query("include_deleted"), "true")

	bookmarks, serverTime, _ := h.svc.GetForUserWithOptions(user.ID, since, includeDeleted)
	c.JSON(http.StatusOK, gin.H{"bookmarks": serializeBookmarks(bookmarks), "server_time": serverTime.Format(time.RFC3339Nano)})
}

func (h *BookmarkHandler) PostSync(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		Changes []bookmarkSyncItem `json:"changes"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	serverNow := time.Now().UTC()
	// Convert to service.BookmarkSyncItem
	changes := make([]service.BookmarkSyncItem, 0, len(req.Changes))
	for _, ch := range req.Changes {
		changes = append(changes, service.BookmarkSyncItem{
			ID:         ch.ID,
			ClientUUID: ch.ClientUUID,
			Title:      ch.Title,
			URL:        ch.URL,
			GroupName:  ch.GroupName,
			SortOrder:  ch.SortOrder,
			IsDeleted:  ch.IsDeleted,
			DeletedAt:  ch.DeletedAt,
			CreatedAt:  ch.CreatedAt,
			UpdatedAt:  ch.UpdatedAt,
		})
	}
	err := h.svc.SyncChanges(user.ID, changes, serverNow)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sync failed"})
		return
	}
	bookmarks, _, _ := h.svc.GetForUserWithOptions(user.ID, time.Time{}, true)
	c.JSON(http.StatusOK, gin.H{"bookmarks": serializeBookmarks(bookmarks), "server_time": time.Now().UTC().Format(time.RFC3339Nano)})
}

func serializeBookmarks(items []models.Bookmark) []bookmarkSyncItem {
	response := make([]bookmarkSyncItem, 0, len(items))
	for _, item := range items {
		response = append(response, bookmarkSyncItem{
			ID:         item.ID,
			ClientUUID: item.ClientUUID,
			Title:      item.Title,
			URL:        item.URL,
			GroupName:  item.GroupName,
			SortOrder:  item.SortOrder,
			IsDeleted:  item.IsDeleted,
			DeletedAt:  item.DeletedAt,
			CreatedAt:  item.CreatedAt.UTC(),
			UpdatedAt:  item.UpdatedAt.UTC(),
		})
	}
	return response
}

func normalizeBookmark(item bookmarkSyncItem) models.Bookmark {
	normalized := models.Bookmark{
		ID:         item.ID,
		ClientUUID: strings.TrimSpace(item.ClientUUID),
		Title:      strings.TrimSpace(item.Title),
		URL:        strings.TrimSpace(item.URL),
		GroupName:  strings.TrimSpace(item.GroupName),
		SortOrder:  item.SortOrder,
		IsDeleted:  item.IsDeleted,
		DeletedAt:  item.DeletedAt,
	}
	if normalized.GroupName == "" {
		normalized.GroupName = "Favorites"
	}
	if normalized.Title == "" {
		normalized.Title = normalized.URL
	}
	if !item.UpdatedAt.IsZero() {
		normalized.UpdatedAt = item.UpdatedAt.UTC()
	}
	if !item.CreatedAt.IsZero() {
		normalized.CreatedAt = item.CreatedAt.UTC()
	}
	return normalized
}

func parseSyncSince(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return parsed.UTC(), nil
	}
	parsed, err = time.Parse(time.RFC3339, raw)
	if err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, err
}
