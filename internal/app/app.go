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
	Config      *config.Config
	DB          *gorm.DB
	OAuthGit    *oauth2.Config
	OAuthGoogle *oauth2.Config
	Router      *gin.Engine
	rateStore   *rateLimiter
	oauthState  map[string]oauthFlowState
}

type oauthFlowState struct {
	UserID   uint
	Redirect string
	Mode     string
}

func New() *App {
	return NewWithConfig(config.Load())
}

// NewWithConfig allows constructing the application with a pre-loaded configuration.
func NewWithConfig(cfg *config.Config) *App {
	db := database.Connect(cfg.DBPath)
	database.MustMigrate(db, &models.User{}, &models.Category{}, &models.Link{}, &models.Bookmark{}, &models.Click{}, &models.Shortcut{})
	database.SeedAdmin(db, cfg.AdminEmail, cfg.AdminPassword, auth.HashPassword)

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubSecret,
		Endpoint:     github.Endpoint,
		Scopes:       []string{"read:user", "user:email"},
		RedirectURL:  cfg.GitHubRedirect,
	}
	googleCfg := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		Scopes:      []string{"openid", "profile", "email"},
		RedirectURL: cfg.GoogleRedirect,
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	a := &App{
		Config:      cfg,
		DB:          db,
		OAuthGit:    oauthCfg,
		OAuthGoogle: googleCfg,
		Router:      r,
		rateStore:   newRateLimiter(),
		oauthState:  make(map[string]oauthFlowState),
	}
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
