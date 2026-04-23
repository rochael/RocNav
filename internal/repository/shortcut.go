package repository

import (
	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

type ShortcutRepository struct {
	db *gorm.DB
}

func NewShortcutRepository(db *gorm.DB) *ShortcutRepository {
	return &ShortcutRepository{db: db}
}

func (r *ShortcutRepository) FindByOwner(ownerID uint) (*models.Shortcut, error) {
	var s models.Shortcut
	err := r.db.Where("owner_id = ?", ownerID).First(&s).Error
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *ShortcutRepository) Upsert(ownerID uint, links string) error {
	return r.db.Where("owner_id = ?", ownerID).Assign(models.Shortcut{Links: links}).FirstOrCreate(&models.Shortcut{OwnerID: ownerID}).Error
}

func (r *ShortcutRepository) Create(s *models.Shortcut) error {
	return r.db.Create(s).Error
}

func (r *ShortcutRepository) Update(s *models.Shortcut) error {
	return r.db.Save(s).Error
}