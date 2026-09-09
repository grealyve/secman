package controller

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/services/vulnjwt"
)

// VulnJWTController, BİLEREK zafiyetli JWT test yüzeyini barındırır. Bu endpoint'ler
// yalnızca DAST tarayıcısının JWT zafiyetlerini izole test etmesi için vardır.
type VulnJWTController struct{}

func NewVulnJWTController() *VulnJWTController { return &VulnJWTController{} }

// demoProfiles: BOLA/subject-confusion için ground-truth demo veritabanı.
// sub -> profil. Her profilin PII'si vardır; başka bir sub'ın verisi "kurban" verisidir.
var demoProfiles = map[string]map[string]interface{}{
	"attacker@secman.io": {
		"sub": "attacker@secman.io", "name": "Mallory", "role": "user",
		"tenant_id": "t-001", "email": "attacker@secman.io", "phone": "555-0100",
	},
	"victim@secman.io": {
		"sub": "victim@secman.io", "name": "Alice", "role": "user",
		"tenant_id": "t-002", "email": "victim@secman.io", "phone": "555-0199",
		"ssn": "123-45-6789", "salary": 145000,
	},
	"admin@secman.io": {
		"sub": "admin@secman.io", "name": "Administrator", "role": "admin",
		"tenant_id": "t-000", "email": "admin@secman.io", "phone": "555-0000",
	},
}

// VulnLogin, saldırganın kendi baseline RS256 token'ını alması için giriş noktası.
// Demo amaçlı parola kontrolü yoktur; verilen email için baseline token üretilir.
func (vc *VulnJWTController) VulnLogin(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
	}
	if c.BindJSON(&body) != nil || body.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "email required"})
		return
	}
	prof, ok := demoProfiles[body.Email]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unknown user"})
		return
	}
	role, _ := prof["role"].(string)
	token, err := vulnjwt.IssueBaselineToken(body.Email, body.Email, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "token error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// VulnJWTS, RS256 public key'i JWK Set olarak servis eder (algorithm-confusion için
// public key kaynağı).
func (vc *VulnJWTController) VulnJWKS(c *gin.Context) {
	c.JSON(http.StatusOK, vulnjwt.JWKS())
}

// VulnAuth, zafiyetli doğrulama middleware'idir. Token'ı VerifyVulnerable ile doğrular
// ve claim'leri context'e koyar. Baseline RS256=200, yanlış imza=401.
func (vc *VulnJWTController) VulnAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			c.Abort()
			return
		}
		tokenString := strings.TrimSpace(strings.Replace(authHeader, "Bearer ", "", 1))
		vt, err := vulnjwt.VerifyVulnerable(tokenString)
		if err != nil {
			logger.Log.Debugf("vulnjwt: token reddedildi: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}
		// VULN-08/10/12: yetki ve kimlik kararları doğrudan token claim'lerinden alınır.
		c.Set("sub", vt.Claims["sub"])
		c.Set("role", vt.Claims["role"])
		c.Set("tenant_id", vt.Claims["tenant_id"])
		c.Next()
	}
}

// VulnProfile, subject-confusion BOLA yüzeyidir. Yetki kararı YOK; token'daki `sub`
// claim'i doğrudan nesne anahtarı olarak kullanılır. sub=kurban -> kurban verisi döner.
func (vc *VulnJWTController) VulnProfile(c *gin.Context) {
	sub, _ := c.Get("sub")
	subStr, _ := sub.(string)
	// VULN-12: erişim, oturum sahibi yerine token'daki sub'a göre yapılır.
	prof, ok := demoProfiles[subStr]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, prof)
}

// VulnAdmin, privilege-escalation yüzeyidir. Erişim yalnızca token'daki `role` claim'ine
// bakılarak verilir (sunucu-tarafı rol store yok).
func (vc *VulnJWTController) VulnAdmin(c *gin.Context) {
	role, _ := c.Get("role")
	// VULN-10: role claim'i tampering ile "admin" yapılırsa tüm veriye erişilir.
	if roleStr, _ := role.(string); !strings.EqualFold(roleStr, "admin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin only"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": demoProfiles})
}

// VulnTenant, tenant-isolation BOLA yüzeyidir. Veri, token'daki `tenant_id` claim'ine
// göre filtrelenir. tenant_id=kurban-tenant -> kurbanın tenant verisi döner.
func (vc *VulnJWTController) VulnTenant(c *gin.Context) {
	tenant, _ := c.Get("tenant_id")
	tenantStr, _ := tenant.(string)
	// VULN-13: tenant izolasyonu yalnız token claim'ine bağlı.
	out := []map[string]interface{}{}
	for _, p := range demoProfiles {
		if tid, _ := p["tenant_id"].(string); tid == tenantStr {
			out = append(out, p)
		}
	}
	c.JSON(http.StatusOK, gin.H{"tenant": tenantStr, "records": out})
}
