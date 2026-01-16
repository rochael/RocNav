package app

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/auth"
	"github.com/rochael/RocNav/internal/config"
	"github.com/rochael/RocNav/internal/database"
	"github.com/rochael/RocNav/internal/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"gorm.io/gorm"
)

type App struct {
	Config    *config.Config
	DB        *gorm.DB
	OAuthGit  *oauth2.Config
	Router    *gin.Engine
	rateStore *rateLimiter
	bindState map[string]uint
}

func New() *App {
	return NewWithConfig(config.Load())
}

// NewWithConfig allows constructing the application with a pre-loaded configuration.
func NewWithConfig(cfg *config.Config) *App {
	db := database.Connect(cfg.DBPath)
	database.MustMigrate(db, &models.User{}, &models.Category{}, &models.Link{}, &models.Click{})
	database.SeedAdmin(db, cfg.AdminEmail, cfg.AdminPassword, auth.HashPassword)

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubSecret,
		Endpoint:     github.Endpoint,
		Scopes:       []string{"read:user", "user:email"},
		RedirectURL:  cfg.GitHubRedirect,
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	a := &App{Config: cfg, DB: db, OAuthGit: oauthCfg, Router: r, rateStore: newRateLimiter(), bindState: make(map[string]uint)}
	a.registerRoutes()
	return a
}

func (a *App) Run() {
	srv := &http.Server{Addr: a.Config.Addr, Handler: a.Router}
	log.Printf("listening on %s", a.Config.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
