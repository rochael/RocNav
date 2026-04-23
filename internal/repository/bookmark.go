package repository

import (
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