package services

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/grealyve/secman/config"
	"github.com/grealyve/secman/logger"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct{}

// GenerateToken generates a JWT for the user
func (s *AuthService) GenerateToken(userID uuid.UUID, role string) (string, error) {
	var secretKey = []byte(config.ConfigInstance.SECRET)
	claims := jwt.MapClaims{
		"id":   userID,
		"role": role,
		"exp":  time.Now().Add(time.Hour * 24).Unix(), // 24 saat geçerli
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func (s *AuthService) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		logger.Log.Errorf("Error comparing password hash: %v", err)
		return false
	}
	return true
}

func (s *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Errorf("Error hashing password: %v", err)
		return "", err
	}
	return string(hash), nil
}
