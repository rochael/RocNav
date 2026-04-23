package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rochael/RocNav/internal/auth"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
)

type AuthService struct {
	userRepo     *repository.UserRepository
	shortcutRepo *repository.ShortcutRepository
	linkRepo     *repository.LinkRepository
	jwtSecret    []byte
	jwtIssuer    string
	jwtTTL       int64
}

func NewAuthService(userRepo *repository.UserRepository, shortcutRepo *repository.ShortcutRepository, linkRepo *repository.LinkRepository, jwtSecret []byte, jwtIssuer string, jwtTTL int64) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		shortcutRepo: shortcutRepo,
		linkRepo:     linkRepo,
		jwtSecret:    jwtSecret,
		jwtIssuer:    jwtIssuer,
		jwtTTL:       jwtTTL,
	}
}

type RegisterRequest struct {
	Email    string
	Password string
	Nickname string
}

type AuthResult struct {
	User       *models.User
	Token      string
	TOTPSecret string
	TOTPURL    string
}

func (s *AuthService) Register(req *RegisterRequest) (*AuthResult, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" || req.Password == "" {
		return nil, errors.New("email and password required")
	}
	if len(req.Password) < 6 {
		return nil, errors.New("password too short")
	}

	secret, urlStr, err := auth.GenerateTOTPSecret(email, s.jwtIssuer)
	if err != nil {
		return nil, errors.New("cannot create totp")
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, errors.New("cannot hash password")
	}

	user := &models.User{
		Email:        email,
		PasswordHash: hash,
		Nickname:     req.Nickname,
		TOTPSecret:   secret,
		Enabled:      true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("user exists")
	}

	// Seed shortcuts from default public links
	if ids, err := s.linkRepo.ListDefaultPublicLinkIDs(); err == nil && len(ids) > 0 {
		strIDs := make([]string, len(ids))
		for i, id := range ids {
			strIDs[i] = fmt.Sprintf("%d", id)
		}
		s.shortcutRepo.Upsert(user.ID, strings.Join(strIDs, ","))
	}

	token, _ := auth.GenerateJWT(s.jwtSecret, s.jwtIssuer, time.Duration(s.jwtTTL)*time.Second, user.ID, user.Email)

	return &AuthResult{
		User:       user,
		Token:      token,
		TOTPSecret: secret,
		TOTPURL:    urlStr,
	}, nil
}

type LoginRequest struct {
	Email    string
	Password string
	OTP      string
}

func (s *AuthService) Login(req *LoginRequest) (*models.User, string, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	if err := auth.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	if !user.Enabled {
		return nil, "", errors.New("user disabled")
	}

	if user.TOTPSecret != "" {
		if req.OTP == "" {
			return nil, "", errors.New("otp required")
		}
		if !auth.ValidateTOTP(user.TOTPSecret, req.OTP) {
			return nil, "", errors.New("invalid otp")
		}
	}

	token, _ := auth.GenerateJWT(s.jwtSecret, s.jwtIssuer, time.Duration(s.jwtTTL)*time.Second, user.ID, user.Email)
	return user, token, nil
}

func (s *AuthService) ChangePassword(userID uint, oldPwd, newPwd string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}
	if err := auth.VerifyPassword(user.PasswordHash, oldPwd); err != nil {
		return errors.New("invalid old password")
	}
	hash, err := auth.HashPassword(newPwd)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	return s.userRepo.Update(user)
}

func (s *AuthService) GetTOTPInfo(user *models.User) (string, string, error) {
	if user.TOTPSecret == "" {
		return "", "", nil
	}
	return user.TOTPSecret, auth.URL(user.TOTPSecret, user.Email, s.jwtIssuer), nil
}

func (s *AuthService) FindUserByEmail(email string) (*models.User, error) {
	return s.userRepo.FindByEmail(email)
}

func (s *AuthService) FindUserByID(id uint) (*models.User, error) {
	return s.userRepo.FindByID(id)
}

func (s *AuthService) UpdateUser(user *models.User) error {
	return s.userRepo.Update(user)
}

func (s *AuthService) GetCurrentUser(tokenStr string) (*models.User, error) {
	if tokenStr == "" {
		return nil, nil
	}
	claims, err := auth.ParseJWT(s.jwtSecret, tokenStr)
	if err != nil {
		return nil, err
	}
	return s.userRepo.FindByID(claims.UserID)
}
