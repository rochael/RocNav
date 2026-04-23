package repository

import (
	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

type ClickRepository struct {
	db *gorm.DB
}

func NewClickRepository(db *gorm.DB) *ClickRepository {
	return &ClickRepository{db: db}
}

func (r *ClickRepository) Create(click *models.Click) error {
	return r.db.Create(click).Error
}