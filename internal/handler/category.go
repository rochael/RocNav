package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
	"github.com/rochael/RocNav/internal/service"
)

type CategoryHandler struct {
	svc *service.CategoryService
}

func NewCategoryHandler(svc *service.CategoryService) *CategoryHandler {
	return &CategoryHandler{svc: svc}
}

func (h *CategoryHandler) List(c *gin.Context) {
	user, _ := c.Get("user")
	var u *models.User
	if user != nil {
		u = user.(*models.User)
	}
	cats, err := h.svc.List(u)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

func (h *CategoryHandler) Create(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	cat, err := h.svc.Create(user, req.Name, req.Description, req.SortOrder)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (h *CategoryHandler) Update(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := c.Param("id")
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	cat, err := h.svc.Update(user, parseUint(id), req.Name, req.Description, req.SortOrder)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (h *CategoryHandler) Delete(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := c.Param("id")
	if err := h.svc.Delete(user, parseUint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CategoryHandler) Reorder(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	var items []repository.SortItem
	if err := c.BindJSON(&items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if err := h.svc.Reorder(user, items); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reorder failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Default categories (admin)

func (h *CategoryHandler) ListDefaults(c *gin.Context) {
	cats, err := h.svc.ListDefaults()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

func (h *CategoryHandler) CreateDefault(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	cat, err := h.svc.CreateDefault(req.Name, req.Description, req.SortOrder)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (h *CategoryHandler) UpdateDefault(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	cat, err := h.svc.UpdateDefault(parseUint(id), req.Name, req.Description, req.SortOrder)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"category": cat})
}

func (h *CategoryHandler) DeleteDefault(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteDefault(parseUint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CategoryHandler) ReorderDefaults(c *gin.Context) {
	var items []repository.SortItem
	if err := c.BindJSON(&items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if err := h.svc.ReorderDefaults(items); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reorder failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func parseUint(s string) uint {
	var v uint
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + uint(c-'0')
		}
	}
	return v
}