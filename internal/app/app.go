package app

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/auth"
	"github.com/rochael/RocNav/internal/config"
	"github.com/rochael/RocNav/internal/database"
	"github.com/rochael/RocNav/internal/handler"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
	"github.com/rochael/RocNav/internal/service"
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

	// 依赖注入
	userRepo       *repository.UserRepository
	categoryRepo   *repository.CategoryRepository
	linkRepo       *repository.LinkRepository
	shortcutRepo   *repository.ShortcutRepository
	clickRepo      *repository.ClickRepository
	bookmarkRepo   *repository.BookmarkRepository

	authSvc        *service.AuthService
	categorySvc    *service.CategoryService
	linkSvc        *service.LinkService
	adminSvc       *service.AdminService
	bookmarkSvc    *service.BookmarkService

	authHandler    *handler.AuthHandler
	categoryHandler *handler.CategoryHandler
	linkHandler    *handler.LinkHandler
	adminHandler   *handler.AdminHandler
	bookmarkHandler *handler.BookmarkHandler
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

	// 初始化 Repository 层
	userRepo := repository.NewUserRepository(db)
	categoryRepo := repository.NewCategoryRepository(db)
	linkRepo := repository.NewLinkRepository(db)
	shortcutRepo := repository.NewShortcutRepository(db)
	clickRepo := repository.NewClickRepository(db)
	bookmarkRepo := repository.NewBookmarkRepository(db)

	// 初始化 Service 层
	authSvc := service.NewAuthService(userRepo, shortcutRepo, linkRepo, cfg.JWTSecret, cfg.JWTIssuer, int64(cfg.JWTTTL/time.Second))
	categorySvc := service.NewCategoryService(categoryRepo)
	linkSvc := service.NewLinkService(linkRepo, clickRepo)
	adminSvc := service.NewAdminService(userRepo, categoryRepo, linkRepo)
	bookmarkSvc := service.NewBookmarkService(bookmarkRepo)

	// 初始化 Handler 层
	authHandler := handler.NewAuthHandler(authSvc, cfg.AllowRegister)
	categoryHandler := handler.NewCategoryHandler(categorySvc)
	linkHandler := handler.NewLinkHandler(linkSvc)
	adminHandler := handler.NewAdminHandler(adminSvc)
	bookmarkHandler := handler.NewBookmarkHandler(bookmarkSvc)

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

		userRepo:       userRepo,
		categoryRepo:   categoryRepo,
		linkRepo:       linkRepo,
		shortcutRepo:   shortcutRepo,
		clickRepo:      clickRepo,
		bookmarkRepo:   bookmarkRepo,

		authSvc:        authSvc,
		categorySvc:    categorySvc,
		linkSvc:        linkSvc,
		adminSvc:       adminSvc,
		bookmarkSvc:    bookmarkSvc,

		authHandler:    authHandler,
		categoryHandler: categoryHandler,
		linkHandler:    linkHandler,
		adminHandler:   adminHandler,
		bookmarkHandler: bookmarkHandler,
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
