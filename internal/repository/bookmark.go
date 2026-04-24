package repository

import (
	"time"

	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

type BookmarkRepository struct {
	db *gorm.DB
}

func NewBookmarkRepository(db *gorm.DB) *BookmarkRepository {
	return &BookmarkRepository{db: db}
}

func (r *BookmarkRepository) DB() *gorm.DB {
	return r.db
}

func (r *BookmarkRepository) Create(b *models.Bookmark) error {
	return r.db.Create(b).Error
}

func (r *BookmarkRepository) Update(b *models.Bookmark) error {
	return r.db.Save(b).Error
}

func (r *BookmarkRepository) Delete(id uint) error {
	return r.db.Delete(&models.Bookmark{}, id).Error
}

func (r *BookmarkRepository) ListByUserAndClient(userID uint, clientUUID string) ([]models.Bookmark, error) {
	var bookmarks []models.Bookmark
	err := r.db.Where("user_id = ? AND client_uuid = ? AND is_deleted = 0", userID, clientUUID).Order("sort_order asc").Find(&bookmarks).Error
	return bookmarks, err
}

func (r *BookmarkRepository) ListAllForUser(userID uint) *gorm.DB {
	return r.db.Where("user_id = ?", userID)
}

func (r *BookmarkRepository) ListActiveByUser(userID uint) ([]models.Bookmark, error) {
	var bookmarks []models.Bookmark
	err := r.db.Where("user_id = ? AND is_deleted = 0", userID).Order("group_name asc, sort_order asc, id asc").Find(&bookmarks).Error
	return bookmarks, err
}

func (r *BookmarkRepository) FindActiveByUserAndID(userID, id uint) (*models.Bookmark, error) {
	var bookmark models.Bookmark
	if err := r.db.Where("user_id = ? AND id = ? AND is_deleted = 0", userID, id).First(&bookmark).Error; err != nil {
		return nil, err
	}
	return &bookmark, nil
}

func (r *BookmarkRepository) SoftDelete(userID, id uint, deletedAt time.Time) error {
	return r.db.Model(&models.Bookmark{}).
		Where("user_id = ? AND id = ? AND is_deleted = 0", userID, id).
		Updates(map[string]any{"is_deleted": true, "deleted_at": deletedAt, "updated_at": deletedAt}).Error
}

func (r *BookmarkRepository) Reorder(userID uint, items []SortItem) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			if err := tx.Model(&models.Bookmark{}).
				Where("user_id = ? AND id = ? AND is_deleted = 0", userID, item.ID).
				Update("sort_order", item.SortOrder).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
