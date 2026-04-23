package repository

import (
	"github.com/rochael/RocNav/internal/models"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}

func (r *UserRepository) List(q string, enabled *bool) ([]models.User, error) {
	var users []models.User
	dbq := r.db.Order("created_at desc")
	if q != "" {
		like := "%" + q + "%"
		dbq = dbq.Where("email LIKE ? OR nickname LIKE ?", like, like)
	}
	if enabled != nil {
		dbq = dbq.Where("enabled = ?", *enabled)
	}
	err := dbq.Find(&users).Error
	return users, err
}