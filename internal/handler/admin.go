package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/service"
)

type AdminHandler struct {
	svc *service.AdminService
}

func NewAdminHandler(svc *service.AdminService) *AdminHandler {
	return &AdminHandler{svc: svc}
}

type adminUserResponse struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	Nickname  string `json:"nickname"`
	IsAdmin   bool   `json:"is_admin"`
	Enabled   bool   `json:"enabled"`
	GitHubID  string `json:"github_id"`
	GoogleID  string `json:"google_id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (h *AdminHandler) ListUsers(c *gin.Context) {
	q := c.Query("q")
	enabledFilter := c.Query("enabled")
	users, err := h.svc.ListUsers(q, enabledFilter)
	if err != nil {
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
			CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": resp})
}

func (h *AdminHandler) UpdateUser(c *gin.Context) {
	actor := c.MustGet("user").(*models.User)
	id := parseUint(c.Param("id"))
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

	// Self-protection checks
	if req.Enabled != nil && !*req.Enabled && actor.ID == id {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot disable yourself"})
		return
	}
	if req.IsAdmin != nil && !*req.IsAdmin && actor.ID == id {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot demote yourself"})
		return
	}

	email := ""
	if req.Email != nil {
		email = *req.Email
	}
	nickname := ""
	if req.Nickname != nil {
		nickname = *req.Nickname
	}

	user, err := h.svc.UpdateUser(id, email, nickname, req.IsAdmin, req.Enabled)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}
