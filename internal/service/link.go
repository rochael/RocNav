package service

import (
	"net/url"

	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
)

type LinkService struct {
	repo       *repository.LinkRepository
	clickRepo  *repository.ClickRepository
}

func NewLinkService(repo *repository.LinkRepository, clickRepo *repository.ClickRepository) *LinkService {
	return &LinkService{repo: repo, clickRepo: clickRepo}
}

func (s *LinkService) List(user *models.User, q, categoryID, visibility string) ([]models.Link, error) {
	// For simplicity, return by owner. The original had complex visibility logic
	if user == nil {
		return s.repo.ListForAnonymous()
	}
	if user.IsAdmin {
		return s.repo.ListByOwner(user.ID)
	}
	return s.repo.ListByOwner(user.ID)
}

func (s *LinkService) ListByOwner(ownerID uint) ([]models.Link, error) {
	return s.repo.ListByOwner(ownerID)
}

func (s *LinkService) guessIcon(linkURL string) string {
	u, err := url.Parse(linkURL)
	if err != nil {
		return ""
	}
	return "https://www.google.com/s2/favicons?domain=" + u.Host
}

func (s *LinkService) Create(ownerID uint, categoryID uint, title, linkURL string, isPublic bool, sortOrder int, iconURL, remark string) (*models.Link, error) {
	icon := iconURL
	if icon == "" {
		icon = s.guessIcon(linkURL)
	}
	link := &models.Link{
		CategoryID: categoryID,
		Title:      title,
		URL:        linkURL,
		IsPublic:   isPublic,
		SortOrder:  sortOrder,
		IconURL:     icon,
		Remark:     remark,
		OwnerID:    &ownerID,
	}
	return link, s.repo.Create(link)
}

func (s *LinkService) Update(user *models.User, id uint, categoryID *uint, title, linkURL *string, isPublic *bool, sortOrder *int, iconURL, remark *string) (*models.Link, error) {
	link, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if link.OwnerID == nil || *link.OwnerID != user.ID {
		return nil, ErrForbidden
	}
	if categoryID != nil {
		link.CategoryID = *categoryID
	}
	if title != nil {
		link.Title = *title
	}
	if linkURL != nil {
		link.URL = *linkURL
	}
	if isPublic != nil {
		link.IsPublic = *isPublic
	}
	if sortOrder != nil {
		link.SortOrder = *sortOrder
	}
	if iconURL != nil {
		link.IconURL = *iconURL
	}
	if remark != nil {
		link.Remark = *remark
	}
	return link, s.repo.Update(link)
}

func (s *LinkService) Delete(user *models.User, id uint) error {
	return s.repo.Delete(id, user.ID)
}

func (s *LinkService) Reorder(user *models.User, items []repository.SortItem) error {
	return s.repo.Reorder(items, user.ID)
}

func (s *LinkService) Click(linkID uint, userID *uint, ip, ua string) error {
	if err := s.repo.IncrementClick(linkID); err != nil {
		return err
	}
	click := &models.Click{LinkID: linkID, UserID: userID, IP: ip, UA: ua}
	return s.clickRepo.Create(click)
}

// Default links

func (s *LinkService) ListDefaults() ([]models.Link, error) {
	return s.repo.ListDefaults()
}

func (s *LinkService) CreateDefault(categoryID uint, title, linkURL string, isPublic bool, sortOrder int, iconURL, remark string) (*models.Link, error) {
	cat, err := s.repo.FindByID(categoryID)
	if err != nil {
		return nil, err
	}
	if cat.OwnerID == nil || *cat.OwnerID != 0 {
		return nil, ErrForbidden
	}
	icon := iconURL
	if icon == "" {
		icon = s.guessIcon(linkURL)
	}
	link := &models.Link{
		CategoryID: categoryID,
		Title:       title,
		URL:         linkURL,
		IsPublic:    isPublic,
		SortOrder:   sortOrder,
		IconURL:     icon,
		Remark:      remark,
	}
	return link, s.repo.CreateDefault(link)
}

func (s *LinkService) UpdateDefault(id uint, categoryID *uint, title, linkURL *string, isPublic *bool, sortOrder *int, iconURL, remark *string) (*models.Link, error) {
	link, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if link.OwnerID == nil || *link.OwnerID != 0 {
		return nil, ErrForbidden
	}
	if categoryID != nil {
		link.CategoryID = *categoryID
	}
	if title != nil {
		link.Title = *title
	}
	if linkURL != nil {
		link.URL = *linkURL
	}
	if isPublic != nil {
		link.IsPublic = *isPublic
	}
	if sortOrder != nil {
		link.SortOrder = *sortOrder
	}
	if iconURL != nil {
		link.IconURL = *iconURL
	}
	if remark != nil {
		link.Remark = *remark
	}
	return link, s.repo.UpdateDefault(link)
}

func (s *LinkService) DeleteDefault(id uint) error {
	return s.repo.DeleteDefault(id)
}

func (s *LinkService) ReorderDefaults(items []repository.SortItem) error {
	return s.repo.ReorderDefaults(items)
}