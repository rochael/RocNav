package models

import "time"

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash string    `gorm:"size:255" json:"-"`
	Nickname     string    `gorm:"size:255" json:"nickname"`
	TOTPSecret   string    `gorm:"size:64" json:"-"`
	GitHubID     string    `gorm:"column:github_id;size:255" json:"github_id"`
	GoogleID     string    `gorm:"column:google_id;size:255" json:"google_id"`
	IsAdmin      bool      `gorm:"default:false" json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Category struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:255;not null" json:"name"`
	Description string    `gorm:"size:512" json:"description"`
	SortOrder   int       `gorm:"index" json:"sort_order"`
	OwnerID     *uint     `gorm:"index" json:"owner_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Link struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	CategoryID uint      `gorm:"index;not null" json:"category_id"`
	Title      string    `gorm:"size:255;not null" json:"title"`
	URL        string    `gorm:"size:1024;not null" json:"url"`
	IsPublic   bool      `gorm:"index" json:"is_public"`
	SortOrder  int       `gorm:"index" json:"sort_order"`
	IconURL    string    `gorm:"size:512" json:"icon_url"`
	Remark     string    `gorm:"size:1024" json:"remark"`
	ClickCount int64     `json:"click_count"`
	OwnerID    *uint     `gorm:"index" json:"owner_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Bookmark struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	UserID     uint       `gorm:"index;not null" json:"user_id"`
	ClientUUID string     `gorm:"size:64;not null;index:idx_bookmarks_user_client,unique" json:"client_uuid"`
	Title      string     `gorm:"size:255;not null" json:"title"`
	URL        string     `gorm:"size:1024;not null" json:"url"`
	GroupName  string     `gorm:"size:255;not null" json:"group_name"`
	SortOrder  int        `gorm:"index" json:"sort_order"`
	IsDeleted  bool       `gorm:"index" json:"is_deleted"`
	DeletedAt  *time.Time `gorm:"index" json:"deleted_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type Click struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	LinkID    uint      `gorm:"index;not null" json:"link_id"`
	UserID    *uint     `gorm:"index" json:"user_id"`
	IP        string    `gorm:"size:64" json:"ip"`
	UA        string    `gorm:"size:512" json:"ua"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}
