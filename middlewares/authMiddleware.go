package middlewares

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/grealyve/secman/config"
	"github.com/grealyve/secman/database"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header not found"})
			c.Abort()
			return
		}

		// "Bearer " önekini kaldır
		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		// Token'ı Redis blacklist'te kontrol et
		blacklisted, err := database.RedisClient.Get(context.Background(), "blacklist:"+tokenString).Result()
		if err == nil && blacklisted == "true" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is blacklisted"})
			c.Abort()
			return
		}

		// Token'ı parse et ve doğrula
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.ConfigInstance.SECRET), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token please log in"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token claims couldn't read"})
			c.Abort()
			return
		}

		// User ID'yi UUID'ye çevir
		userID, err := uuid.Parse(claims["id"].(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid User ID"})
			c.Abort()
			return
		}

		// Kullanıcı bilgilerini context'e ekle
		c.Set("userID", userID)
		c.Set("role", claims["role"])

		c.Next()
	}
}
