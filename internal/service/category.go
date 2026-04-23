package service

import (
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
)

type CategoryService struct {
	repo *repository.CategoryRepository
}

func NewCategoryService(repo *repository.CategoryRepository) *CategoryService {
	return &CategoryService{repo: repo}
}

type ListCategoriesResult struct {
	Categories []models.Category
}

func (s *CategoryService) List(user *models.User) ([]models.Category, error) {
	if user == nil {
		return s.repo.ListForAnonymous()
	}
	if user.IsAdmin {
		return s.repo.ListByOwner(user.ID)
	}
	return s.repo.ListByOwner(user.ID)
}

func (s *CategoryService) ListForUser(userID uint) ([]models.Category, error) {
	return s.repo.ListByOwner(userID)
}

func (s *CategoryService) Create(user *models.User, name, description string, sortOrder int) (*models.Category, error) {
	cat := &models.Category{
		Name:        name,
		Description: description,
		SortOrder:   sortOrder,
		OwnerID:     &user.ID,
	}
	return cat, s.repo.Create(cat)
}

func (s *CategoryService) Update(user *models.User, id uint, name, description *string, sortOrder *int) (*models.Category, error) {
	cat, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if cat.OwnerID == nil || *cat.OwnerID != user.ID {
		return nil, ErrForbidden
	}
	if name != nil {
		cat.Name = *name
	}
	if description != nil {
		cat.Description = *description
	}
	if sortOrder != nil {
		cat.SortOrder = *sortOrder
	}
	return cat, s.repo.Update(cat)
}

func (s *CategoryService) Delete(user *models.User, id uint) error {
	return s.repo.Delete(id, user.ID)
}

func (s *CategoryService) Reorder(user *models.User, items []repository.SortItem) error {
	return s.repo.Reorder(items, user.ID)
}

// Default categories (admin only)

func (s *CategoryService) ListDefaults() ([]models.Category, error) {
	return s.repo.ListDefaults()
}

func (s *CategoryService) CreateDefault(name, description string, sortOrder int) (*models.Category, error) {
	cat := &models.Category{
		Name:        name,
		Description: description,
		SortOrder:   sortOrder,
	}
	return cat, s.repo.CreateDefault(cat)
}

func (s *CategoryService) UpdateDefault(id uint, name, description *string, sortOrder *int) (*models.Category, error) {
	cat, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if name != nil {
		cat.Name = *name
	}
	if description != nil {
		cat.Description = *description
	}
	if sortOrder != nil {
		cat.SortOrder = *sortOrder
	}
	return cat, s.repo.UpdateDefault(cat)
}

func (s *CategoryService) DeleteDefault(id uint) error {
	return s.repo.DeleteDefault(id)
}

func (s *CategoryService) ReorderDefaults(items []repository.SortItem) error {
	return s.repo.ReorderDefaults(items)
}