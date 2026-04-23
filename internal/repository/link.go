package repository

import (
	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

type LinkRepository struct {
	db *gorm.DB
}

func NewLinkRepository(db *gorm.DB) *LinkRepository {
	return &LinkRepository{db: db}
}

func (r *LinkRepository) FindByID(id uint) (*models.Link, error) {
	var link models.Link
	err := r.db.First(&link, id).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// ListByOwner returns links owned by a specific user (owner_id = userID, NOT 0)
func (r *LinkRepository) ListByOwner(userID uint) ([]models.Link, error) {
	var links []models.Link
	err := r.db.Where("owner_id = ?", userID).Order("sort_order asc, id asc").Find(&links).Error
	return links, err
}

// ListDefaults returns system default links (owner_id = 0)
func (r *LinkRepository) ListDefaults() ([]models.Link, error) {
	var links []models.Link
	err := r.db.Where("owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&links).Error
	return links, err
}

// ListForAnonymous returns public default links visible to anonymous users
func (r *LinkRepository) ListForAnonymous() ([]models.Link, error) {
	var links []models.Link
	err := r.db.Where("is_public = 1 AND owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&links).Error
	return links, err
}

// ListPublicAndOwn returns public links and links owned by the user
func (r *LinkRepository) ListPublicAndOwn(userID uint) ([]models.Link, error) {
	var links []models.Link
	err := r.db.Where("is_public = 1 OR owner_id = ?", userID).Order("sort_order asc, id asc").Find(&links).Error
	return links, err
}

func (r *LinkRepository) Create(link *models.Link) error {
	return r.db.Create(link).Error
}

func (r *LinkRepository) Update(link *models.Link) error {
	return r.db.Save(link).Error
}

// Delete removes a link owned by a specific user
func (r *LinkRepository) Delete(id uint, ownerID uint) error {
	return r.db.Where("id = ? AND owner_id = ?", id, ownerID).Delete(&models.Link{}).Error
}

// DeleteDefault removes a system default link
func (r *LinkRepository) DeleteDefault(id uint) error {
	return r.db.Where("id = ? AND owner_id = ?", id, zeroOwnerID).Delete(&models.Link{}).Error
}

func (r *LinkRepository) Reorder(items []SortItem, ownerID uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			if err := tx.Model(&models.Link{}).Where("id = ? AND owner_id = ?", item.ID, ownerID).Update("sort_order", item.SortOrder).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *LinkRepository) ReorderDefaults(items []SortItem) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			if err := tx.Model(&models.Link{}).Where("id = ? AND owner_id = ?", item.ID, zeroOwnerID).Update("sort_order", item.SortOrder).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateDefault creates a system default link
func (r *LinkRepository) CreateDefault(link *models.Link) error {
	link.OwnerID = &zeroOwnerID
	return r.db.Create(link).Error
}

// UpdateDefault updates a system default link
func (r *LinkRepository) UpdateDefault(link *models.Link) error {
	if link.OwnerID == nil || *link.OwnerID != zeroOwnerID {
		return gorm.ErrRecordNotFound
	}
	return r.db.Save(link).Error
}

// IncrementClick increments click_count by 1
func (r *LinkRepository) IncrementClick(id uint) error {
	return r.db.Model(&models.Link{}).Where("id = ?", id).UpdateColumn("click_count", gorm.Expr("click_count + 1")).Error
}

// ListDefaultIDs returns IDs of public default links (for shortcut seeding)
func (r *LinkRepository) ListDefaultPublicLinkIDs() ([]uint, error) {
	var ids []uint
	err := r.db.Model(&models.Link{}).Where("is_public = 1 AND owner_id = ?", zeroOwnerID).Pluck("id", &ids).Error
	return ids, err
}
