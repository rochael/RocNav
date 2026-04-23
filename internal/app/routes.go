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

	a.Router.GET("/api/auth/me", a.authHandler.Me)
	a.Router.POST("/api/auth/register", a.authHandler.Register)
	a.Router.POST("/api/auth/login", a.authHandler.Login)
	a.Router.POST("/api/auth/logout", a.authHandler.Logout)
	a.Router.POST("/api/auth/password", a.authRequired(), a.authHandler.ChangePassword)
	a.Router.GET("/api/auth/totp", a.authRequired(), a.authHandler.GetTOTP)
	a.Router.GET("/api/auth/github/start", a.handleGitHubStart)
	a.Router.GET("/api/auth/github/callback", a.handleGitHubCallback)
	a.Router.GET("/api/auth/google/start", a.handleGoogleStart)
	a.Router.GET("/api/auth/google/callback", a.handleGoogleCallback)

	a.Router.GET("/api/admin/users", a.adminRequired(), a.adminHandler.ListUsers)
	a.Router.PUT("/api/admin/users/:id", a.adminRequired(), a.adminHandler.UpdateUser)

	a.Router.GET("/api/admin/default-categories", a.adminRequired(), a.categoryHandler.ListDefaults)
	a.Router.POST("/api/admin/default-categories", a.adminRequired(), a.categoryHandler.CreateDefault)
	a.Router.PUT("/api/admin/default-categories/:id", a.adminRequired(), a.categoryHandler.UpdateDefault)
	a.Router.DELETE("/api/admin/default-categories/:id", a.adminRequired(), a.categoryHandler.DeleteDefault)
	a.Router.PUT("/api/admin/default-categories/reorder", a.adminRequired(), a.categoryHandler.ReorderDefaults)

	a.Router.GET("/api/admin/default-links", a.adminRequired(), a.linkHandler.ListDefaults)
	a.Router.POST("/api/admin/default-links", a.adminRequired(), a.linkHandler.CreateDefault)
	a.Router.PUT("/api/admin/default-links/:id", a.adminRequired(), a.linkHandler.UpdateDefault)
	a.Router.DELETE("/api/admin/default-links/:id", a.adminRequired(), a.linkHandler.DeleteDefault)
	a.Router.PUT("/api/admin/default-links/reorder", a.adminRequired(), a.linkHandler.ReorderDefaults)

	a.Router.GET("/api/categories", a.optionalAuth(), a.categoryHandler.List)
	a.Router.POST("/api/categories", a.authRequired(), a.categoryHandler.Create)
	a.Router.PUT("/api/categories/:id", a.authRequired(), a.categoryHandler.Update)
	a.Router.DELETE("/api/categories/:id", a.authRequired(), a.categoryHandler.Delete)
	a.Router.PUT("/api/categories/reorder", a.authRequired(), a.categoryHandler.Reorder)

	a.Router.GET("/api/links", a.optionalAuth(), a.linkHandler.List)
	a.Router.POST("/api/links", a.authRequired(), a.linkHandler.Create)
	a.Router.PUT("/api/links/:id", a.authRequired(), a.linkHandler.Update)
	a.Router.DELETE("/api/links/:id", a.authRequired(), a.linkHandler.Delete)
	a.Router.PUT("/api/links/reorder", a.authRequired(), a.linkHandler.Reorder)
	a.Router.POST("/api/links/:id/click", a.linkHandler.Click)

	a.Router.GET("/api/bookmarks/sync", a.authRequired(), a.handleGetBookmarkSync)
	a.Router.POST("/api/bookmarks/sync", a.authRequired(), a.handlePostBookmarkSync)
	a.Router.GET("/api/mobile/shortcut-catalog", a.handleMobileShortcutCatalog)
	a.Router.GET("/api/mobile/shortcuts", a.handleMobileShortcuts)
	a.Router.PUT("/api/mobile/shortcuts", a.authRequired(), a.handleUpdateMobileShortcuts)

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

func (a *App) optionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := a.currentUser(c)
		if err == nil {
			c.Set("user", user)
		}
		if err != nil && err.Error() != "no token" {
			a.clearToken(c)
		}
		c.Next()
	}
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

func (a *App) adminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := a.currentUser(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if !user.IsAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
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
	if !user.Enabled {
		a.clearToken(c)
		return nil, errors.New("user disabled")
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
	githubEnabled := a.OAuthGit != nil && strings.TrimSpace(a.OAuthGit.ClientID) != ""
	googleEnabled := a.OAuthGoogle != nil && strings.TrimSpace(a.OAuthGoogle.ClientID) != ""
	user, err := a.currentUser(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"user":                 nil,
			"allow_register":       a.Config.AllowRegister,
			"github_oauth_enabled": githubEnabled,
			"google_oauth_enabled": googleEnabled,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user":                 userResponse(user),
		"allow_register":       a.Config.AllowRegister,
		"github_oauth_enabled": githubEnabled,
		"google_oauth_enabled": googleEnabled,
	})
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
	u := models.User{Email: req.Email, PasswordHash: hash, Nickname: req.Nickname, TOTPSecret: secret, Enabled: true}
	if err := a.DB.Create(&u).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user exists"})
		return
	}
	var defaultLinkIDs []uint
	a.DB.Model(&models.Link{}).Where("is_public = 1 AND owner_id = 0").Pluck("id", &defaultLinkIDs)
	if len(defaultLinkIDs) > 0 {
		ids := make([]string, len(defaultLinkIDs))
		for i, id := range defaultLinkIDs {
			ids[i] = fmt.Sprintf("%d", id)
		}
		a.DB.Create(&models.Shortcut{OwnerID: u.ID, Links: strings.Join(ids, ",")})
	}
	token, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
	a.setToken(c, token)
	c.JSON(http.StatusOK, gin.H{"user": userResponse(&u), "token": token, "totp_secret": secret, "totp_url": urlStr})
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
	if !u.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "user disabled"})
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
	c.JSON(http.StatusOK, gin.H{"user": userResponse(&u), "token": token})
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

func (a *App) startOAuth(c *gin.Context, cfg *oauth2.Config, provider string) {
	if cfg == nil || cfg.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": provider + " oauth not configured"})
		return
	}
	state := fmt.Sprintf("st_%d", time.Now().UnixNano())
	flowState := oauthFlowState{
		Redirect: strings.TrimSpace(c.Query("redirect")),
		Mode:     strings.TrimSpace(c.Query("mode")),
	}
	if c.Query("bind") == "1" {
		if u, err := a.currentUser(c); err == nil && u != nil {
			flowState.UserID = u.ID
		}
	}
	a.oauthState[state] = flowState
	url := cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
	c.JSON(http.StatusOK, gin.H{"url": url, "state": state})
}

func (a *App) handleGitHubStart(c *gin.Context) {
	a.startOAuth(c, a.OAuthGit, "github")
}

func (a *App) handleGoogleStart(c *gin.Context) {
	a.startOAuth(c, a.OAuthGoogle, "google")
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
	ghID := fmt.Sprintf("%d", ghUser.ID)
	updates := map[string]any{"github_id": ghID}
	if err := a.completeOAuth(c, ghID, "github_id", updates, strings.ToLower(email), ghUser.Login, "github account already bound"); err != nil {
		a.respondOAuthError(c, err)
	}
}

func (a *App) handleGoogleCallback(c *gin.Context) {
	if a.OAuthGoogle == nil || a.OAuthGoogle.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "google oauth not configured"})
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}
	token, err := a.OAuthGoogle.Exchange(c, code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "exchange failed"})
		return
	}
	googleUser, err := fetchGoogleUser(c, token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "google user fetch failed"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(googleUser.Email))
	if email == "" {
		email = fmt.Sprintf("google_%s@users.noreply.local", googleUser.ID)
	}
	nickname := strings.TrimSpace(googleUser.Name)
	if nickname == "" {
		nickname = strings.TrimSpace(googleUser.Email)
	}
	updates := map[string]any{"google_id": googleUser.ID}
	if err := a.completeOAuth(c, googleUser.ID, "google_id", updates, email, nickname, "google account already bound"); err != nil {
		a.respondOAuthError(c, err)
	}
}

func (a *App) oauthRedirectURL(token string, flowState oauthFlowState, fallbackRedirect string) string {
	redirect := strings.TrimSpace(flowState.Redirect)
	if redirect == "" {
		redirect = strings.TrimSpace(fallbackRedirect)
	}
	if redirect == "" {
		if flowState.Mode == "mobile" {
			redirect = "rocnav://auth/github"
		} else {
			redirect = a.Config.FrontendOrigin
		}
	}
	if flowState.Mode != "mobile" {
		return redirect
	}

	parsed, err := url.Parse(redirect)
	if err != nil {
		return redirect
	}
	query := parsed.Query()
	query.Set("token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (a *App) handleListUsers(c *gin.Context) {
	q := strings.TrimSpace(strings.ToLower(c.Query("q")))
	enabledFilter := strings.TrimSpace(strings.ToLower(c.Query("enabled")))

	type adminUserResponse struct {
		ID        uint      `json:"id"`
		Email     string    `json:"email"`
		Nickname  string    `json:"nickname"`
		IsAdmin   bool      `json:"is_admin"`
		Enabled   bool      `json:"enabled"`
		GitHubID  string    `json:"github_id"`
		GoogleID  string    `json:"google_id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	dbq := a.DB.Model(&models.User{}).Order("created_at desc, id desc")
	if q != "" {
		like := fmt.Sprintf("%%%s%%", q)
		dbq = dbq.Where("LOWER(email) LIKE ? OR LOWER(nickname) LIKE ?", like, like)
	}
	switch enabledFilter {
	case "true", "1":
		dbq = dbq.Where("enabled = ?", true)
	case "false", "0":
		dbq = dbq.Where("enabled = ?", false)
	}

	var users []models.User
	if err := dbq.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}

	resp := make([]adminUserResponse, 0, len(users))
	for _, user := range users {
		resp = append(resp, adminUserResponse{
			ID:        user.ID,
			Email:     user.Email,
			Nickname:  user.Nickname,
			IsAdmin:   user.IsAdmin,
			Enabled:   user.Enabled,
			GitHubID:  user.GitHubID,
			GoogleID:  user.GoogleID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": resp})
}

func (a *App) handleUpdateUser(c *gin.Context) {
	actor := c.MustGet("user").(*models.User)
	var target models.User
	if err := a.DB.First(&target, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	var req struct {
		Email    *string `json:"email"`
		Nickname *string `json:"nickname"`
		IsAdmin  *bool   `json:"is_admin"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	if req.Enabled != nil && !*req.Enabled && actor.ID == target.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot disable yourself"})
		return
	}
	if req.IsAdmin != nil && !*req.IsAdmin && actor.ID == target.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot demote yourself"})
		return
	}
	if req.IsAdmin != nil && target.IsAdmin && !*req.IsAdmin {
		var adminCount int64
		a.DB.Model(&models.User{}).Where("is_admin = ?", true).Count(&adminCount)
		if adminCount <= 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot revoke last admin"})
			return
		}
	}

	updates := map[string]any{}
	if req.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email required"})
			return
		}
		updates["email"] = email
	}
	if req.Nickname != nil {
		updates["nickname"] = strings.TrimSpace(*req.Nickname)
	}
	if req.IsAdmin != nil {
		updates["is_admin"] = *req.IsAdmin
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}
	if err := a.DB.Model(&target).Updates(updates).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	if err := a.DB.First(&target, target.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": userResponse(&target)})
}

func (a *App) handleListCategories(c *gin.Context) {
	var categories []models.Category
	user, _ := a.currentUser(c)
	dbq := a.DB.Order("sort_order asc, id asc")
	if user == nil {
		dbq = dbq.Where("owner_id IS NULL")
	} else if user.IsAdmin {
		dbq = dbq.Where("owner_id != 0")
	} else {
		dbq = dbq.Where("owner_id = ?", user.ID)
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
		dbq = dbq.Where("is_public = 1 AND owner_id != 0")
	} else if user.IsAdmin {
		dbq = dbq.Where("owner_id != 0")
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

var zeroOwnerID uint = 0

func (a *App) handleListDefaultCategories(c *gin.Context) {
	var categories []models.Category
	a.DB.Where("owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&categories)
	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

func (a *App) handleCreateDefaultCategory(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	cat := models.Category{Name: req.Name, Description: req.Description, SortOrder: req.SortOrder, OwnerID: &zeroOwnerID}
	if err := a.DB.Create(&cat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (a *App) handleUpdateDefaultCategory(c *gin.Context) {
	id := c.Param("id")
	var cat models.Category
	if err := a.DB.First(&cat, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if cat.OwnerID == nil || *cat.OwnerID != zeroOwnerID {
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

func (a *App) handleDeleteDefaultCategory(c *gin.Context) {
	id := c.Param("id")
	var cat models.Category
	if err := a.DB.First(&cat, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if cat.OwnerID == nil || *cat.OwnerID != zeroOwnerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	a.DB.Delete(&cat)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleReorderDefaultCategories(c *gin.Context) {
	var items []struct {
		ID        uint `json:"id"`
		SortOrder int  `json:"sort_order"`
	}
	if err := c.BindJSON(&items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	for _, item := range items {
		a.DB.Model(&models.Category{}).Where("id = ? AND owner_id = ?", item.ID, zeroOwnerID).Update("sort_order", item.SortOrder)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleListDefaultLinks(c *gin.Context) {
	var links []models.Link
	a.DB.Where("owner_id = ?", zeroOwnerID).Order("sort_order asc, id asc").Find(&links)
	c.JSON(http.StatusOK, gin.H{"links": links})
}

func (a *App) handleCreateDefaultLink(c *gin.Context) {
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
	var cat models.Category
	if err := a.DB.First(&cat, req.CategoryID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category not found"})
		return
	}
	if cat.OwnerID == nil || *cat.OwnerID != zeroOwnerID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category must be a default category"})
		return
	}
	icon := req.IconURL
	if icon == "" {
		icon = guessIcon(req.URL)
	}
	link := models.Link{CategoryID: req.CategoryID, Title: req.Title, URL: req.URL, IsPublic: req.IsPublic, SortOrder: req.SortOrder, IconURL: icon, Remark: req.Remark, OwnerID: &zeroOwnerID}
	if err := a.DB.Create(&link).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (a *App) handleUpdateDefaultLink(c *gin.Context) {
	id := c.Param("id")
	var link models.Link
	if err := a.DB.First(&link, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if link.OwnerID == nil || *link.OwnerID != zeroOwnerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	var req struct {
		CategoryID *uint   `json:"category_id"`
		Title      *string `json:"title"`
		URL        *string `json:"url"`
		IsPublic   *bool   `json:"is_public"`
		SortOrder  *int    `json:"sort_order"`
		IconURL    *string `json:"icon_url"`
		Remark     *string `json:"remark"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.CategoryID != nil {
		var cat models.Category
		if err := a.DB.First(&cat, *req.CategoryID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "category not found"})
			return
		}
		if cat.OwnerID == nil || *cat.OwnerID != zeroOwnerID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "category must be a default category"})
			return
		}
		link.CategoryID = *req.CategoryID
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
	if err := a.DB.Save(&link).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (a *App) handleDeleteDefaultLink(c *gin.Context) {
	id := c.Param("id")
	var link models.Link
	if err := a.DB.First(&link, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if link.OwnerID == nil || *link.OwnerID != zeroOwnerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	a.DB.Delete(&link)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) handleReorderDefaultLinks(c *gin.Context) {
	var items []struct {
		ID        uint `json:"id"`
		SortOrder int  `json:"sort_order"`
	}
	if err := c.BindJSON(&items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	for _, item := range items {
		a.DB.Model(&models.Link{}).Where("id = ? AND owner_id = ?", item.ID, zeroOwnerID).Update("sort_order", item.SortOrder)
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

func (a *App) completeOAuth(c *gin.Context, providerID, field string, updates map[string]any, email, nickname, boundErr string) error {
	state := c.Query("state")
	currentFlowState := oauthFlowState{
		Redirect: strings.TrimSpace(c.Query("redirect")),
		Mode:     strings.TrimSpace(c.Query("mode")),
	}
	if flowState, ok := a.oauthState[state]; ok {
		currentFlowState = flowState
		delete(a.oauthState, state)
		if flowState.UserID == 0 {
			goto loginOrCreate
		}
		var u models.User
		if err := a.DB.First(&u, flowState.UserID).Error; err != nil {
			return fmt.Errorf("user not found")
		}
		if !u.Enabled {
			return errors.New("user disabled")
		}
		var count int64
		a.DB.Model(&models.User{}).Where(field+" = ? AND id <> ?", providerID, u.ID).Count(&count)
		if count > 0 {
			return errors.New(boundErr)
		}
		if err := a.DB.Model(&u).Updates(updates).Error; err != nil {
			return fmt.Errorf("update user failed")
		}
		tok, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
		a.setToken(c, tok)
		c.Redirect(http.StatusFound, a.oauthRedirectURL(tok, flowState, c.Query("redirect")))
		return nil
	}

loginOrCreate:
	var u models.User
	if err := a.DB.Where(field+" = ?", providerID).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u = models.User{Email: email, Nickname: nickname, Enabled: true}
			for k, v := range updates {
				switch k {
				case "github_id":
					u.GitHubID = v.(string)
				case "google_id":
					u.GoogleID = v.(string)
				}
			}
			if err := a.DB.Create(&u).Error; err != nil {
				return fmt.Errorf("create user failed")
			}
		} else {
			return fmt.Errorf("query user failed")
		}
	}
	if !u.Enabled {
		return errors.New("user disabled")
	}
	tok, _ := auth.GenerateJWT(a.Config.JWTSecret, a.Config.JWTIssuer, a.Config.JWTTTL, u.ID, u.Email)
	a.setToken(c, tok)
	c.Redirect(http.StatusFound, a.oauthRedirectURL(tok, currentFlowState, c.Query("redirect")))
	return nil
}

func (a *App) respondOAuthError(c *gin.Context, err error) {
	switch err.Error() {
	case "user not found":
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case "github account already bound", "google account already bound":
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case "user disabled":
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case "create user failed", "query user failed", "update user failed":
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
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
	return gin.H{"id": u.ID, "email": u.Email, "nickname": u.Nickname, "enabled": u.Enabled, "is_admin": u.IsAdmin, "github_id": u.GitHubID, "google_id": u.GoogleID}
}

type gitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

type googleUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
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

func fetchGoogleUser(c *gin.Context, token *oauth2.Token) (*googleUser, error) {
	client := oauth2.NewClient(c, oauth2.StaticTokenSource(token))
	var user googleUser
	if err := getJSON(client, "https://www.googleapis.com/oauth2/v2/userinfo", &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func getJSON(client *http.Client, url string, dest any) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("oauth status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

func guessIcon(link string) string {
	u, err := url.Parse(link)
	if err != nil || u.Host == "" {
		return ""
	}
	return fmt.Sprintf("https://www.google.com/s2/favicons?domain=%s&sz=64", u.Host)
}
