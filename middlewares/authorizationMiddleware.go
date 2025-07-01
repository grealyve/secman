package middlewares

import (
	"net/http"

	"slices"

	"github.com/gin-gonic/gin"
	"github.com/grealyve/lutenix/logger"
)

var permissionMap = map[string]map[string][]string{
	"admin": {
		"scan":    {"create", "read", "update", "delete"},
		"scanner": {"use", "configure", "read", "create", "update", "delete"},
		"asset":   {"read", "create", "update", "delete"},
		"user":    {"read", "create", "update", "delete", "logout"},
		"admin":   {"create", "read", "update", "delete"},
	},
	"user": {
		"scan":    {"create", "read", "update", "delete"},
		"asset":   {"read", "create", "update", "delete"},
		"scanner": {"use", "configure", "read"},
		"user":    {"read", "update", "logout"},
	},
}

func Authorization(resource string, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authentication middleware'den gelen role'ü al
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Rol bilgisi bulunamadı"})
			logger.Log.Info("Rol bilgisi bulunamadı")
			c.Abort()
			return
		}

		// Role string'e çevir
		roleStr := role.(string)

		// Role için izinleri kontrol et
		if permissions, ok := permissionMap[roleStr]; ok {
			if resourcePerms, ok := permissions[resource]; ok {
				// İstenen action'ın izinler arasında olup olmadığını kontrol et
				if slices.Contains(resourcePerms, action) {
					c.Next()
					return
				}
			}
		}

		// İzin yoksa erişimi reddet
		c.JSON(http.StatusForbidden, gin.H{"error": "Bu işlem için yetkiniz bulunmamaktadır"})
		logger.Log.Errorf("Bu işlem için yetkin yok: %v", roleStr)
		c.Abort()
	}
}
