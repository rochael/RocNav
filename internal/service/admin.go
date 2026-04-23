package service

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
	"golang.org/x/oauth2"
)

type OAuthState struct {
	Redirect string
	Mode    string
	UserID  uint
}

type AdminService struct {
	userRepo  *repository.UserRepository
	catRepo   *repository.CategoryRepository
	linkRepo  *repository.LinkRepository
}

func NewAdminService(userRepo *repository.UserRepository, catRepo *repository.CategoryRepository, linkRepo *repository.LinkRepository) *AdminService {
	return &AdminService{
		userRepo: userRepo,
		catRepo:  catRepo,
		linkRepo: linkRepo,
	}
}

func (s *AdminService) ListUsers(q string, enabledFilter string) ([]models.User, error) {
	var enabled *bool
	switch enabledFilter {
	case "enabled":
		t := true
		enabled = &t
	case "disabled":
		t := false
		enabled = &t
	}
	return s.userRepo.List(q, enabled)
}

func (s *AdminService) UpdateUser(id uint, email, nickname string, isAdmin, enabled *bool) (*models.User, error) {
	user, err := s.userRepo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if email != "" {
		user.Email = email
	}
	if nickname != "" {
		user.Nickname = nickname
	}
	if isAdmin != nil {
		user.IsAdmin = *isAdmin
	}
	if enabled != nil {
		user.Enabled = *enabled
	}
	return user, s.userRepo.Update(user)
}

type OAuthProvider struct {
	Config *oauth2.Config
	Name   string
}

func GenerateOAuthState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}