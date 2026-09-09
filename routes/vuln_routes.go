package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
)

// VulnJWTRoutes, BİLEREK zafiyetli JWT test yüzeyini kaydeder.
//   POST /api/v1/vuln/login          -> baseline RS256 token al
//   GET  /.well-known/jwks.json      -> RS256 public key (algorithm-confusion kaynağı)
//   GET  /api/v1/vuln/profile        -> subject-confusion BOLA (sub claim'ine göre)
//   GET  /api/v1/vuln/admin          -> privilege escalation (role claim'ine göre)
//   GET  /api/v1/vuln/tenant         -> tenant isolation BOLA (tenant_id claim'ine göre)
func VulnJWTRoutes(router *gin.Engine) {
	vc := controller.NewVulnJWTController()

	router.GET("/.well-known/jwks.json", vc.VulnJWKS)

	vuln := router.Group("/api/v1/vuln")
	vuln.POST("/login", vc.VulnLogin)

	authed := vuln.Group("")
	authed.Use(vc.VulnAuth())
	{
		authed.GET("/profile", vc.VulnProfile)
		authed.GET("/admin", vc.VulnAdmin)
		authed.GET("/tenant", vc.VulnTenant)
	}
}
