package service

import (
	"strings"
	"time"

	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
	"gorm.io/gorm"
)

type BookmarkService struct {
	db *repository.BookmarkRepository
}

func NewBookmarkService(db *repository.BookmarkRepository) *BookmarkService {
	return &BookmarkService{db: db}
}

func (s *BookmarkService) GetForUser(userID uint, clientUUID string) ([]models.Bookmark, error) {
	return s.db.ListByUserAndClient(userID, clientUUID)
}

func (s *BookmarkService) GetForUserWithOptions(userID uint, since time.Time, includeDeleted bool) ([]models.Bookmark, time.Time, error) {
	var bookmarks []models.Bookmark
	dbq := s.db.ListAllForUser(userID)
	if !since.IsZero() {
		dbq = dbq.Where("updated_at > ?", since)
	}
	if !includeDeleted {
		dbq = dbq.Where("is_deleted = 0")
	}
	dbq.Order("sort_order asc, id asc").Find(&bookmarks)
	return bookmarks, time.Now().UTC(), nil
}

func (s *BookmarkService) SyncChanges(userID uint, changes []BookmarkSyncItem, serverNow time.Time) error {
	return s.db.DB().Transaction(func(tx *gorm.DB) error {
		for _, change := range changes {
			if strings.TrimSpace(change.ClientUUID) == "" {
				continue
			}
			incoming := normalizeServiceBookmark(change, serverNow)

			var bookmark models.Bookmark
			query := tx.Where("user_id = ?", userID)
			lookupErr := gorm.ErrRecordNotFound
			if incoming.ID != 0 {
				lookupErr = query.Where("id = ?", incoming.ID).First(&bookmark).Error
			}
			if incoming.ID == 0 || lookupErr == gorm.ErrRecordNotFound {
				lookupErr = tx.Where("user_id = ? AND client_uuid = ?", userID, incoming.ClientUUID).First(&bookmark).Error
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
					UserID:     userID,
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
}

type BookmarkSyncItem struct {
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

func normalizeServiceBookmark(item BookmarkSyncItem, fallback time.Time) models.Bookmark {
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

func (s *BookmarkService) Sync(userID uint, clientUUID string, incoming []models.Bookmark) error {
	existing, err := s.db.ListByUserAndClient(userID, clientUUID)
	if err != nil {
		return err
	}

	// Build maps
	existingMap := make(map[string]*models.Bookmark)
	for i := range existing {
		existingMap[existing[i].ClientUUID] = &existing[i]
	}
	incomingMap := make(map[string]bool)
	for _, b := range incoming {
		incomingMap[b.ClientUUID] = true
	}

	// Delete removed
	for _, e := range existing {
		if !incomingMap[e.ClientUUID] {
			s.db.Delete(e.ID)
		}
	}

	// Upsert incoming
	for _, b := range incoming {
		b.UserID = userID
		if existing, ok := existingMap[b.ClientUUID]; ok {
			if b.UpdatedAt.After(existing.UpdatedAt) {
				b.ID = existing.ID
				s.db.Update(&b)
			}
		} else {
			s.db.Create(&b)
		}
	}
	return nil
}