package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
)

// InternalRoutes registers the deliberately undocumented "internal" surface (see
// controller.SystemController). These routes are served under /api, so the sensor in front of
// Secman sees their traffic, but no OpenAPI spec lists them: they are the shadow endpoints an
// API inventory is expected to find. GET only, no authentication, no state.
func InternalRoutes(router *gin.Engine) {
	system := controller.NewSystemController()

	internal := router.Group("/api/v1/internal")
	{
		internal.GET("/debug/config", system.DebugConfig)
		internal.GET("/tenants/:tenant_id/flags", system.TenantFlags)
	}
}
