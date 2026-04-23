package repository

import (
	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

var zeroOwnerID uint = 0

type SortItem struct {
	ID       uint `json:"id"`
	SortOrder int  `json:"sort_order"`
}

type CategoryRepository struct {
	db *gorm.DB
}

func NewCategoryRepository(db *gorm.DB) *CategoryRepository {
	return &CategoryRepository{db: db}
}

// ListByOwner returns categories owned by a specific user (owner_id = userID, NOT 0)
func (r *CategoryRepository) ListByOwner(userID uint) ([]models.Category, error) {
	var cats []models.Category
	err := r.db.Where("owner_id = ?", userID).Order("sort_order asc, id asc").Find(&cats).Error
	return cats, err
}

// ListDefaults returns system default categories (owner_id = 0)
func (r *CategoryRepository) ListDefaults() ([]models.Category, error) {
	var cats []models.Category
	err := r.db.Where("owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&cats).Error
	return cats, err
}

// ListForAnonymous returns categories visible to anonymous users (owner_id IS NULL)
func (r *CategoryRepository) ListForAnonymous() ([]models.Category, error) {
	var cats []models.Category
	err := r.db.Where("owner_id IS NULL").Order("sort_order asc, id asc").Find(&cats).Error
	return cats, err
}

func (r *CategoryRepository) FindByID(id uint) (*models.Category, error) {
	var cat models.Category
	err := r.db.First(&cat, id).Error
	if err != nil {
		return nil, err
	}
	return &cat, nil
}

func (r *CategoryRepository) Create(cat *models.Category) error {
	return r.db.Create(cat).Error
}

func (r *CategoryRepository) Update(cat *models.Category) error {
	return r.db.Save(cat).Error
}

// Delete removes a category owned by a specific user
func (r *CategoryRepository) Delete(id uint, ownerID uint) error {
	return r.db.Where("id = ? AND owner_id = ?", id, ownerID).Delete(&models.Category{}).Error
}

// DeleteDefault removes a system default category
func (r *CategoryRepository) DeleteDefault(id uint) error {
	return r.db.Where("id = ? AND owner_id = ?", id, zeroOwnerID).Delete(&models.Category{}).Error
}

func (r *CategoryRepository) Reorder(items []SortItem, ownerID uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			if err := tx.Model(&models.Category{}).Where("id = ? AND owner_id = ?", item.ID, ownerID).Update("sort_order", item.SortOrder).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CategoryRepository) ReorderDefaults(items []SortItem) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			if err := tx.Model(&models.Category{}).Where("id = ? AND owner_id = ?", item.ID, zeroOwnerID).Update("sort_order", item.SortOrder).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateDefault creates a system default category
func (r *CategoryRepository) CreateDefault(cat *models.Category) error {
	cat.OwnerID = &zeroOwnerID
	return r.db.Create(cat).Error
}

// UpdateDefault updates a system default category
func (r *CategoryRepository) UpdateDefault(cat *models.Category) error {
	if cat.OwnerID == nil || *cat.OwnerID != zeroOwnerID {
		return gorm.ErrRecordNotFound
	}
	return r.db.Save(cat).Error
}