package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"id"`
	CompanyID uuid.UUID `gorm:"type:uuid;not null" json:"company_id"`
	Name      string    `gorm:"type:varchar(1000);not null" json:"name"`
	Surname   string    `gorm:"type:varchar(1000);not null" json:"surname"`
	Email     string    `gorm:"type:varchar(255);unique;not null" json:"email"`
	Password  string    `gorm:"type:varchar(255);not null" json:"password"`
	Role      string    `gorm:"type:varchar(20);not null" json:"role"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	Company   Company   `gorm:"foreignKey:CompanyID" json:"-"`
}
