package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/services/vulnjwt"
)

// Authentication, MERGE (LTX) sonrası uygulamanın TEK auth middleware'idir. Token'ı
// BİLEREK zafiyetli vulnjwt.VerifyVulnerable ile doğrular (alg:none/algorithm-confusion/
// kid/embedded/jku + exp/aud/iss doğrulaması yok). Böylece admin/zap/semgrep/users dahil
// her korumalı yüzey aynı kırık JWT auth'una dayanır. Kimlik/yetki kararları doğrudan
// (forge edilebilir) token claim'lerinden alınır: id -> userID, role, sub, tenant_id.
func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header not found"})
			c.Abort()
			return
		}

		// "Bearer " önekini kaldır
		tokenString := strings.TrimSpace(strings.Replace(authHeader, "Bearer ", "", 1))

		// Token'ı Redis blacklist'te kontrol et (logout korunur)
		blacklisted, err := database.RedisClient.Get(context.Background(), "blacklist:"+tokenString).Result()
		if err == nil && blacklisted == "true" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is blacklisted"})
			c.Abort()
			return
		}

		// VULN: zafiyetli doğrulama. Baseline RS256=kabul, yanlış imza=ret; forge
		// vektörleri (alg:none vb.) bilerek kabul edilir.
		vt, err := vulnjwt.VerifyVulnerable(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token please log in"})
			c.Abort()
			return
		}

		// VULN-12: uygulama kimliği doğrudan token'ın `id` claim'inden alınır (forge -> BOLA).
		idStr, _ := vt.Claims["id"].(string)
		userID, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid User ID"})
			c.Abort()
			return
		}

		// Kimlik/yetki claim'lerini context'e koy. role/sub/tenant_id string'e normalize edilir.
		c.Set("userID", userID)
		c.Set("role", claimString(vt.Claims["role"]))
		c.Set("sub", claimString(vt.Claims["sub"]))
		c.Set("tenant_id", claimString(vt.Claims["tenant_id"]))

		c.Next()
	}
}

// claimString, bir JWT claim'ini güvenli şekilde string'e çevirir (nil -> "").
func claimString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
