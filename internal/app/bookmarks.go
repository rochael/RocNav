package app

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

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

func (a *App) handleGetBookmarkSync(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	since, err := parseSyncSince(c.Query("since"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid since"})
		return
	}
	includeDeleted := c.Query("include_deleted") == "1" || strings.EqualFold(c.Query("include_deleted"), "true")

	bookmarks, serverTime := a.loadBookmarksForSync(user.ID, since, includeDeleted)
	c.JSON(http.StatusOK, gin.H{
		"bookmarks":   serializeBookmarks(bookmarks),
		"server_time": serverTime.Format(time.RFC3339Nano),
	})
}

func (a *App) handlePostBookmarkSync(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		Changes []bookmarkSyncItem `json:"changes"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	serverNow := time.Now().UTC()
	err := a.DB.Transaction(func(tx *gorm.DB) error {
		for _, change := range req.Changes {
			if strings.TrimSpace(change.ClientUUID) == "" {
				continue
			}
			incoming := normalizeBookmarkChange(change, serverNow)

			var bookmark models.Bookmark
			query := tx.Where("user_id = ?", user.ID)
			lookupErr := gorm.ErrRecordNotFound
			if incoming.ID != 0 {
				lookupErr = query.Where("id = ?", incoming.ID).First(&bookmark).Error
			}
			if incoming.ID == 0 || lookupErr == gorm.ErrRecordNotFound {
				lookupErr = tx.Where("user_id = ? AND client_uuid = ?", user.ID, incoming.ClientUUID).First(&bookmark).Error
			}
			if lookupErr != nil && lookupErr != gorm.ErrRecordNotFound {
				return lookupErr
			}

			if lookupErr == gorm.ErrRecordNotFound {
				createdAt := incoming.CreatedAt
				if createdAt.IsZero() {
					createdAt = incoming.UpdatedAt
				}
				bookmark = models.Bookmark{
					UserID:     user.ID,
					ClientUUID: incoming.ClientUUID,
					Title:      incoming.Title,
					URL:        incoming.URL,
					GroupName:  incoming.GroupName,
					SortOrder:  incoming.SortOrder,
					IsDeleted:  incoming.IsDeleted,
					DeletedAt:  incoming.DeletedAt,
					CreatedAt:  createdAt,
					UpdatedAt:  incoming.UpdatedAt,
				}
				if err := tx.Create(&bookmark).Error; err != nil {
					return err
				}
				continue
			}

			if bookmark.UpdatedAt.After(incoming.UpdatedAt) {
				continue
			}

			bookmark.ClientUUID = incoming.ClientUUID
			bookmark.Title = incoming.Title
			bookmark.URL = incoming.URL
			bookmark.GroupName = incoming.GroupName
			bookmark.SortOrder = incoming.SortOrder
			bookmark.IsDeleted = incoming.IsDeleted
			bookmark.DeletedAt = incoming.DeletedAt
			bookmark.UpdatedAt = incoming.UpdatedAt
			if incoming.CreatedAt.After(time.Time{}) && incoming.CreatedAt.Before(bookmark.CreatedAt) {
				bookmark.CreatedAt = incoming.CreatedAt
			}
			if err := tx.Save(&bookmark).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sync failed"})
		return
	}

	bookmarks, serverTime := a.loadBookmarksForSync(user.ID, time.Time{}, true)
	c.JSON(http.StatusOK, gin.H{
		"bookmarks":   serializeBookmarks(bookmarks),
		"server_time": serverTime.Format(time.RFC3339Nano),
	})
}

func (a *App) loadBookmarksForSync(userID uint, since time.Time, includeDeleted bool) ([]models.Bookmark, time.Time) {
	var bookmarks []models.Bookmark
	dbq := a.DB.Where("user_id = ?", userID).Order("sort_order asc, id asc")
	if !since.IsZero() {
		dbq = dbq.Where("updated_at > ?", since)
	}
	if !includeDeleted {
		dbq = dbq.Where("is_deleted = 0")
	}
	dbq.Find(&bookmarks)
	sort.Slice(bookmarks, func(i, j int) bool {
		if bookmarks[i].SortOrder == bookmarks[j].SortOrder {
			return bookmarks[i].ID < bookmarks[j].ID
		}
		return bookmarks[i].SortOrder < bookmarks[j].SortOrder
	})
	return bookmarks, time.Now().UTC()
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

func normalizeBookmarkChange(item bookmarkSyncItem, fallback time.Time) bookmarkSyncItem {
	normalized := item
	normalized.ClientUUID = strings.TrimSpace(item.ClientUUID)
	normalized.Title = strings.TrimSpace(item.Title)
	normalized.URL = strings.TrimSpace(item.URL)
	normalized.GroupName = strings.TrimSpace(item.GroupName)
	if normalized.GroupName == "" {
		normalized.GroupName = "Favorites"
	}
	if normalized.Title == "" {
		normalized.Title = normalized.URL
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = fallback
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = normalized.UpdatedAt
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.IsDeleted {
		if normalized.DeletedAt == nil || normalized.DeletedAt.IsZero() {
			deletedAt := normalized.UpdatedAt
			normalized.DeletedAt = &deletedAt
		} else {
			deletedAt := normalized.DeletedAt.UTC()
			normalized.DeletedAt = &deletedAt
		}
	} else {
		normalized.DeletedAt = nil
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
