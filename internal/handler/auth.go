package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/service"
)

type AuthHandler struct {
	svc      *service.AuthService
	allowReg bool
}

func NewAuthHandler(svc *service.AuthService, allowReg bool) *AuthHandler {
	return &AuthHandler{svc: svc, allowReg: allowReg}
}

func (h *AuthHandler) Me(c *gin.Context) {
	user, _ := h.getCurrentUser(c)
	c.JSON(http.StatusOK, gin.H{
		"user":           userResponse(user),
		"allow_register": h.allowReg,
	})
}

func (h *AuthHandler) Register(c *gin.Context) {
	if !h.allowReg {
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
	result, err := h.svc.Register(&service.RegisterRequest{
		Email:    req.Email,
		Password: req.Password,
		Nickname: req.Nickname,
	})
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.setTokenCookie(c, result.Token)
	c.JSON(http.StatusOK, gin.H{"user": userResponse(result.User), "token": result.Token, "totp_secret": result.TOTPSecret, "totp_url": result.TOTPURL})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	user, token, err := h.svc.Login(&service.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
		OTP:      req.OTP,
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	h.setTokenCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"user": userResponse(user), "token": token})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	h.clearTokenCookie(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if err := h.svc.ChangePassword(user.ID, req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthHandler) GetTOTP(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	secret, urlStr, err := h.svc.GetTOTPInfo(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot get totp"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret, "url": urlStr})
}

func (h *AuthHandler) getCurrentUser(c *gin.Context) (*models.User, error) {
	tokenStr := ""
	if ck, err := c.Cookie("nav_token"); err == nil {
		tokenStr = ck
	}
	if tokenStr == "" {
		authz := c.GetHeader("Authorization")
		if len(authz) > 7 && authz[:7] == "Bearer " {
			tokenStr = authz[7:]
		}
	}
	if tokenStr == "" {
		return nil, nil
	}
	return h.svc.GetCurrentUser(tokenStr)
}

func (h *AuthHandler) setTokenCookie(c *gin.Context, token string) {
	c.SetCookie("nav_token", token, 86400, "/", "", false, true)
}

func (h *AuthHandler) clearTokenCookie(c *gin.Context) {
	c.SetCookie("nav_token", "", -1, "/", "", false, true)
}

func userResponse(u *models.User) any {
	if u == nil {
		return nil
	}
	return gin.H{
		"id":        u.ID,
		"email":     u.Email,
		"nickname":  u.Nickname,
		"enabled":   u.Enabled,
		"is_admin":  u.IsAdmin,
		"github_id": u.GitHubID,
		"google_id": u.GoogleID,
	}
}

func getCurrentUserFromContext(c *gin.Context) *models.User {
	if u, ok := c.Get("user"); ok {
		return u.(*models.User)
	}
	return nil
}

