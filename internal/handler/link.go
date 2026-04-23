package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rochael/RocNav/internal/models"
	"github.com/rochael/RocNav/internal/repository"
	"github.com/rochael/RocNav/internal/service"
)

type LinkHandler struct {
	svc *service.LinkService
}

func NewLinkHandler(svc *service.LinkService) *LinkHandler {
	return &LinkHandler{svc: svc}
}

func (h *LinkHandler) List(c *gin.Context) {
	user, _ := c.Get("user")
	var u *models.User
	if user != nil {
		u = user.(*models.User)
	}
	q := c.Query("q")
	categoryID := c.Query("category_id")
	visibility := c.Query("visibility")
	links, err := h.svc.List(u, q, categoryID, visibility)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"links": links})
}

func (h *LinkHandler) Create(c *gin.Context) {
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
	link, err := h.svc.Create(user.ID, req.CategoryID, req.Title, req.URL, req.IsPublic, req.SortOrder, req.IconURL, req.Remark)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (h *LinkHandler) Update(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := parseUint(c.Param("id"))
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
	link, err := h.svc.Update(user, id, req.CategoryID, req.Title, req.URL, req.IsPublic, req.SortOrder, req.IconURL, req.Remark)
	if err != nil {
		if err == service.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if err == service.ErrForbidden {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (h *LinkHandler) Delete(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	id := parseUint(c.Param("id"))
	if err := h.svc.Delete(user, id); err != nil {
		if err == service.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if err == service.ErrForbidden {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *LinkHandler) Reorder(c *gin.Context) {
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

func (h *LinkHandler) Click(c *gin.Context) {
	id := parseUint(c.Param("id"))
	ip := c.ClientIP()
	ua := c.GetHeader("User-Agent")
	var userID *uint
	if u, ok := c.Get("user"); ok {
		if u := u.(*models.User); u != nil {
			userID = &u.ID
		}
	}
	if err := h.svc.Click(id, userID, ip, ua); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "click failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Default links

func (h *LinkHandler) ListDefaults(c *gin.Context) {
	links, err := h.svc.ListDefaults()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"links": links})
}

func (h *LinkHandler) CreateDefault(c *gin.Context) {
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
	link, err := h.svc.CreateDefault(req.CategoryID, req.Title, req.URL, req.IsPublic, req.SortOrder, req.IconURL, req.Remark)
	if err != nil {
		if err == service.ErrForbidden {
			c.JSON(http.StatusBadRequest, gin.H{"error": "category must be a default category"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (h *LinkHandler) UpdateDefault(c *gin.Context) {
	id := parseUint(c.Param("id"))
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
	link, err := h.svc.UpdateDefault(id, req.CategoryID, req.Title, req.URL, req.IsPublic, req.SortOrder, req.IconURL, req.Remark)
	if err != nil {
		if err == service.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if err == service.ErrForbidden {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"link": link})
}

func (h *LinkHandler) DeleteDefault(c *gin.Context) {
	id := parseUint(c.Param("id"))
	if err := h.svc.DeleteDefault(id); err != nil {
		if err == service.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if err == service.ErrForbidden {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *LinkHandler) ReorderDefaults(c *gin.Context) {
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
