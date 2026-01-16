package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/auth"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/web"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

const tokenCookie = "nav_token"

func (a *App) registerRoutes() {
	a.Router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{a.Config.FrontendOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	a.Router.GET("/api/auth/me", a.handleMe)
	a.Router.POST("/api/auth/register", a.handleRegister)
	a.Router.POST("/api/auth/login", a.handleLogin)
	a.Router.POST("/api/auth/logout", a.handleLogout)
	a.Router.POST("/api/auth/password", a.authRequired(), a.handleChangePassword)
	a.Router.GET("/api/auth/totp", a.authRequired(), a.handleTOTPInfo)
	a.Router.GET("/api/auth/github/start", a.handleGitHubStart)
	a.Router.GET("/api/auth/github/callback", a.handleGitHubCallback)

	a.Router.GET("/api/categories", a.handleListCategories)
	a.Router.POST("/api/categories", a.authRequired(), a.handleCreateCategory)
	a.Router.PUT("/api/categories/:id", a.authRequired(), a.handleUpdateCategory)
	a.Router.DELETE("/api/categories/:id", a.authRequired(), a.handleDeleteCategory)
	a.Router.PUT("/api/categories/reorder", a.authRequired(), a.handleReorderCategories)

	a.Router.GET("/api/links", a.handleListLinks)
	a.Router.POST("/api/links", a.authRequired(), a.handleCreateLink)
	a.Router.PUT("/api/links/:id", a.authRequired(), a.handleUpdateLink)
	a.Router.DELETE("/api/links/:id", a.authRequired(), a.handleDeleteLink)
	a.Router.PUT("/api/links/reorder", a.authRequired(), a.handleReorderLinks)
	a.Router.POST("/api/links/:id/click", a.handleClickLink)

	// Static files for frontend (Embedded)
	distFS, _ := web.GetDistFS()
	indexBytes, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		panic("index.html missing in embedded frontend build")
	}
	assetsFS, _ := fs.Sub(distFS, "assets")
	a.Router.StaticFS("/assets", http.FS(assetsFS))

	a.Router.GET("/vite.svg", func(c *gin.Context) {
		c.FileFromFS("vite.svg", http.FS(distFS))
	})

	// Root path
	a.Router.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexBytes)
	})

	// SPA fallback
	a.Router.NoRoute(func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.Data(http.StatusOK, "text/html; charset=utf-8", indexBytes)
		}
	})
}

func (a *App) authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := a.currentUser(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

func (a *App) currentUser(c *gin.Context) (*models.User, error) {
	token := ""
	if ck, err := c.Cookie(tokenCookie); err == nil {
		token = ck
	}
	if token == "" {
		authz := c.GetHeader("Authorization")
		if strings.HasPrefix(authz, "Bearer ") {
			token = strings.TrimPrefix(authz, "Bearer ")
		}
	}
	if token == "" {
		return nil, errors.New("no token")
	}
	claims, err := auth.ParseJWT(a.Config.JWTSecret, token)
	if err != nil {
		return nil, err
	}
	var user models.User
	if err := a.DB.First(&user, claims.UserID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *App) setToken(c *gin.Context, token string) {
	httpOnly := true
	sameSite := http.SameSiteLaxMode
	c.SetCookie(tokenCookie, token, int(a.Config.JWTTTL.Seconds()), "/", a.Config.CookieDomain, a.Config.CookieSecure, httpOnly)
	c.Writer.Header().Add("Set-Cookie", (&http.Cookie{Name: tokenCookie, Value: token, Path: "/", Domain: a.Config.CookieDomain, MaxAge: int(a.Config.JWTTTL.Seconds()), HttpOnly: httpOnly, SameSite: sameSite, Secure: a.Config.CookieSecure}).String())
}

func (a *App) clearToken(c *gin.Context) {
	httpOnly := true
	sameSite := http.SameSiteLaxMode
	c.SetCookie(tokenCookie, "", -1, "/", a.Config.CookieDomain, a.Config.CookieSecure, httpOnly)
	c.Writer.Header().Add("Set-Cookie", (&http.Cookie{Name: tokenCookie, Value: "", Path: "/", Domain: a.Config.CookieDomain, MaxAge: -1, HttpOnly: httpOnly, SameSite: sameSite, Secure: a.Config.CookieSecure}).String())
}

func (a *App) handleMe(c *gin.Context) {
	user, err := a.currentUser(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"user": nil, "allow_register": a.Config.AllowRegister})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": userResponse(user), "allow_register": a.Config.AllowRegister})
}

func (a *App) handleRegister(c *gin.Context) {
	if !a.Config.AllowRegister {
		c.JSON(http.StatusForbidden, gin.H{"error": "registration disabled"})
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Nickname string `json:"nickname"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password required"})
		return
	}
	if len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password too short"})
		return
	}
	secret, urlStr, err := auth.GenerateTOTPSecret(req.Email, a.Config.JWTIssuer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create totp"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot hash password"})
		return
	}
	u := models.User{Email: req.Email, PasswordHash: hash, Nickname: req.Nickname, TOTPSecret: secret}
	if err := a.DB.Create(&u).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user exists"})
		return
	}
	token, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
	a.setToken(c, token)
	c.JSON(http.StatusOK, gin.H{"user": userResponse(&u), "totp_secret": secret, "totp_url": urlStr})
}

func (a *App) handleLogin(c *gin.Context) {
	if !a.rateStore.Allow("login:" + c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts"})
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	var u models.User
	if err := a.DB.Where("email = ?", strings.ToLower(req.Email)).First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if u.PasswordHash == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "use oauth login"})
		return
	}
	if err := auth.VerifyPassword(u.PasswordHash, req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !auth.ValidateTOTP(u.TOTPSecret, req.OTP) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid otp"})
		return
	}
	token, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
	a.setToken(c, token)
	c.JSON(http.StatusOK, gin.H{"user": userResponse(&u)})
}

func (a *App) handleChangePassword(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&req); err != nil || req.OldPassword == "" || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if len(req.NewPassword) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password too short"})
		return
	}
	if user.PasswordHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password login not enabled"})
		return
	}
	if err := auth.VerifyPassword(user.PasswordHash, req.OldPassword); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot hash password"})
		return
	}
	a.DB.Model(user).Update("password_hash", newHash)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleLogout(c *gin.Context) {
	a.clearToken(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleTOTPInfo(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	urlStr := ""
	if user.TOTPSecret != "" {
		urlStr = auth.URL(user.TOTPSecret, user.Email, a.Config.JWTIssuer)
	}
	c.JSON(http.StatusOK, gin.H{"secret": user.TOTPSecret, "url": urlStr})
}

func (a *App) handleGitHubStart(c *gin.Context) {
	if a.OAuthGit == nil || a.OAuthGit.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "github oauth not configured"})
		return
	}
	state := fmt.Sprintf("st_%d", time.Now().UnixNano())
	if c.Query("bind") == "1" {
		if u, err := a.currentUser(c); err == nil && u != nil {
			a.bindState[state] = u.ID
		}
	}
	url := a.OAuthGit.AuthCodeURL(state, oauth2.AccessTypeOnline)
	c.JSON(http.StatusOK, gin.H{"url": url, "state": state})
}

func (a *App) handleGitHubCallback(c *gin.Context) {
	if a.OAuthGit == nil || a.OAuthGit.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "github oauth not configured"})
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}
	token, err := a.OAuthGit.Exchange(c, code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "exchange failed"})
		return
	}
	ghUser, email, err := fetchGitHubUser(c, token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "github user fetch failed"})
		return
	}
	if email == "" {
		email = fmt.Sprintf("github_%d@users.noreply.github.com", ghUser.ID)
	}
	state := c.Query("state")
	if uid, ok := a.bindState[state]; ok {
		delete(a.bindState, state)
		var u models.User
		if err := a.DB.First(&u, uid).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}
		ghID := fmt.Sprintf("%d", ghUser.ID)
		// ensure not bound to others
		var count int64
		a.DB.Model(&models.User{}).Where("github_id = ? AND id <> ?", ghID, u.ID).Count(&count)
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "github account already bound"})
			return
		}
		a.DB.Model(&u).Updates(map[string]any{"github_id": ghID, "nickname": u.Nickname})
		tok, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
		a.setToken(c, tok)
		redirect := c.Query("redirect")
		if redirect == "" {
			redirect = a.Config.FrontendOrigin
		}
		c.Redirect(http.StatusFound, redirect)
		return
	}
	var u models.User
	ghID := fmt.Sprintf("%d", ghUser.ID)
	if err := a.DB.Where("github_id = ?", ghID).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u = models.User{GitHubID: ghID, Email: strings.ToLower(email), Nickname: ghUser.Login}
			if err := a.DB.Create(&u).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "create user failed"})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "query user failed"})
			return
		}
	}
	tok, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
	a.setToken(c, tok)
	redirect := c.Query("redirect")
	if redirect == "" {
		redirect = a.Config.FrontendOrigin
	}
	c.Redirect(http.StatusFound, redirect)
}

func (a *App) handleListCategories(c *gin.Context) {
	var categories []models.Category
	user, _ := a.currentUser(c)
	dbq := a.DB.Order("sort_order asc, id asc")
	if user == nil {
		dbq = dbq.Where("owner_id IS NULL")
	} else if !user.IsAdmin {
		dbq = dbq.Where("owner_id = ? OR owner_id IS NULL", user.ID)
	}
	dbq.Find(&categories)
	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

func (a *App) handleCreateCategory(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	cat := models.Category{Name: req.Name, Description: req.Description, SortOrder: req.SortOrder, OwnerID: &user.ID}
	if err := a.DB.Create(&cat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (a *App) handleUpdateCategory(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := c.Param("id")
	var cat models.Category
	if err := a.DB.First(&cat, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !ownsOrAdmin(user, cat.OwnerID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Name != nil {
		cat.Name = *req.Name
	}
	if req.Description != nil {
		cat.Description = *req.Description
	}
	if req.SortOrder != nil {
		cat.SortOrder = *req.SortOrder
	}
	if err := a.DB.Save(&cat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (a *App) handleDeleteCategory(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := c.Param("id")
	var cat models.Category
	if err := a.DB.First(&cat, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !ownsOrAdmin(user, cat.OwnerID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	a.DB.Delete(&cat)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleReorderCategories(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var items []struct {
		ID        uint `json:"id"`
		SortOrder int  `json:"sort_order"`
	}
	if err := c.BindJSON(&items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	for _, item := range items {
		a.DB.Model(&models.Category{}).Where("id = ? AND (owner_id = ? OR ?)", item.ID, user.ID, user.IsAdmin).Update("sort_order", item.SortOrder)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleListLinks(c *gin.Context) {
	user, _ := a.currentUser(c)
	var links []models.Link
	q := strings.TrimSpace(c.Query("q"))
	categoryID := c.Query("category_id")
	visibility := c.Query("visibility")

	dbq := a.DB.Order("sort_order asc, id asc")
	if q != "" {
		like := fmt.Sprintf("%%%s%%", q)
		dbq = dbq.Where("title LIKE ?", like)
	}
	if categoryID != "" {
		dbq = dbq.Where("category_id = ?", categoryID)
	}
	if user == nil {
		dbq = dbq.Where("is_public = 1")
	} else if user.IsAdmin {
		// admin sees all, but keep visibility filters if explicitly requested
		switch visibility {
		case "private":
			dbq = dbq.Where("is_public = 0")
		case "all":
			// no-op, all records
		default:
			dbq = dbq.Where("is_public = 1")
		}
	} else {
		switch visibility {
		case "private":
			dbq = dbq.Where("is_public = 0 AND owner_id = ?", user.ID)
		case "all":
			dbq = dbq.Where("owner_id = ?", user.ID)
		default:
			dbq = dbq.Where("is_public = 1").Or("owner_id = ?", user.ID)
		}
	}
	dbq.Find(&links)
	c.JSON(http.StatusOK, gin.H{"links": links})
}

func (a *App) handleCreateLink(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		CategoryID uint   `json:"category_id"`
		Title      string `json:"title"`
		URL        string `json:"url"`
		IsPublic   bool   `json:"is_public"`
		SortOrder  int    `json:"sort_order"`
		IconURL    string `json:"icon_url"`
		Remark     string `json:"remark"`
	}
	if err := c.BindJSON(&req); err != nil || req.Title == "" || req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	icon := req.IconURL
	if icon == "" {
		icon = guessIcon(req.URL)
	}
	link := models.Link{CategoryID: req.CategoryID, Title: req.Title, URL: req.URL, IsPublic: req.IsPublic, SortOrder: req.SortOrder, IconURL: icon, Remark: req.Remark, OwnerID: &user.ID}
	if err := a.DB.Create(&link).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (a *App) handleUpdateLink(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := c.Param("id")
	var link models.Link
	if err := a.DB.First(&link, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !ownsOrAdmin(user, link.OwnerID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	var req struct {
		Title     *string `json:"title"`
		URL       *string `json:"url"`
		IsPublic  *bool   `json:"is_public"`
		SortOrder *int    `json:"sort_order"`
		IconURL   *string `json:"icon_url"`
		Remark    *string `json:"remark"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.Title != nil {
		link.Title = *req.Title
	}
	if req.URL != nil {
		link.URL = *req.URL
	}
	if req.IsPublic != nil {
		link.IsPublic = *req.IsPublic
	}
	if req.SortOrder != nil {
		link.SortOrder = *req.SortOrder
	}
	if req.IconURL != nil {
		link.IconURL = *req.IconURL
	}
	if req.Remark != nil {
		link.Remark = *req.Remark
	}
	if link.IconURL == "" {
		link.IconURL = guessIcon(link.URL)
	}
	if err := a.DB.Save(&link).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (a *App) handleDeleteLink(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := c.Param("id")
	var link models.Link
	if err := a.DB.First(&link, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !ownsOrAdmin(user, link.OwnerID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	a.DB.Delete(&link)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleReorderLinks(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var items []struct {
		ID        uint `json:"id"`
		SortOrder int  `json:"sort_order"`
	}
	if err := c.BindJSON(&items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	for _, item := range items {
		a.DB.Model(&models.Link{}).Where("id = ? AND (owner_id = ? OR ?)", item.ID, user.ID, user.IsAdmin).Update("sort_order", item.SortOrder)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleClickLink(c *gin.Context) {
	id := c.Param("id")
	var link models.Link
	if err := a.DB.First(&link, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	user, _ := a.currentUser(c)
	a.DB.Model(&models.Link{}).Where("id = ?", link.ID).UpdateColumn("click_count", gorm.Expr("click_count + 1"))
	rec := models.Click{LinkID: link.ID}
	if user != nil {
		rec.UserID = &user.ID
	}
	rec.IP = c.ClientIP()
	rec.UA = c.GetHeader("User-Agent")
	a.DB.Create(&rec)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func ownsOrAdmin(u *models.User, ownerID *uint) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin {
		return true
	}
	if ownerID == nil {
		return false
	}
	return *ownerID == u.ID
}

func userResponse(u *models.User) gin.H {
	if u == nil {
		return nil
	}
	return gin.H{"id": u.ID, "email": u.Email, "nickname": u.Nickname, "is_admin": u.IsAdmin, "github_id": u.GitHubID}
}

type gitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

func fetchGitHubUser(c *gin.Context, token *oauth2.Token) (*gitHubUser, string, error) {
	client := oauth2.NewClient(c, oauth2.StaticTokenSource(token))
	var user gitHubUser
	if err := getJSON(client, "https://api.github.com/user", &user); err != nil {
		return nil, "", err
	}
	email := user.Email
	if email == "" {
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := getJSON(client, "https://api.github.com/user/emails", &emails); err == nil {
			for _, e := range emails {
				if e.Primary {
					email = e.Email
					break
				}
			}
			if email == "" && len(emails) > 0 {
				email = emails[0].Email
			}
		}
	}
	return &user, email, nil
}

func getJSON(client *http.Client, url string, dest any) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("github status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

func guessIcon(link string) string {
	u, err := url.Parse(link)
	if err != nil || u.Host == "" {
		return ""
	}
	return fmt.Sprintf("https://www.google.com/s2/favicons?domain=%s", u.Host)
}
