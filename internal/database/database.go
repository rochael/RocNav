package database

import (
	"fmt"
	"log"
	"os"

	"github.com/rochael/RocNav/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Connect(path string) *gorm.DB {
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		log.Fatalf("create db dir: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	return db
}

func dir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

func MustMigrate(db *gorm.DB, models ...any) {
	if err := db.AutoMigrate(models...); err != nil {
		log.Fatalf("migrate: %v", err)
	}
}

func SeedAdmin(db *gorm.DB, email, password string, hashFunc func(string) (string, error)) {
	if email == "" || password == "" {
		return
	}
	var count int64
	db.Model(&models.User{}).Where("email = ?", email).Count(&count)
	if count > 0 {
		return
	}
	hash, err := hashFunc(password)
	if err != nil {
		log.Printf("seed admin hash: %v", err)
		return
	}
	u := models.User{Email: email, PasswordHash: hash, Nickname: "Admin", IsAdmin: true}
	if err := db.Create(&u).Error; err != nil {
		log.Printf("seed admin create: %v", err)
	} else {
		fmt.Println("seeded admin user", email)
	}
}
