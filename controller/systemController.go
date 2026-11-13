package controller

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
)

// SystemController serves the operational endpoints: the health check and the "internal"
// surface below.
//
// DELIBERATELY UNDOCUMENTED (shadow API test surface). Secman is a scan target, and these
// handlers exist so an inventory tool has something real to find:
//   - the /api/v1/internal/* routes are served but appear in no OpenAPI spec (shadow endpoints);
//   - GET /health accepts a `verbose` query parameter the spec does not declare (shadow
//     parameter).
//
// Do not add them to the spec: that would remove what they are for. They are read-only and
// touch neither the database nor Redis, so calling them never changes the application's state.
type SystemController struct {
	startedAt time.Time
}

func NewSystemController() *SystemController {
	return &SystemController{startedAt: time.Now()}
}

// Health is the documented health check. With ?verbose=true it also returns runtime details:
// the undeclared parameter.
func (sc *SystemController) Health(c *gin.Context) {
	body := gin.H{
		"status":    "ok",
		"message":   "SecMan is running",
		"timestamp": "2025-06-30",
	}
	if c.Query("verbose") == "true" {
		body["runtime"] = gin.H{
			"go_version":     runtime.Version(),
			"goroutines":     runtime.NumGoroutine(),
			"uptime_seconds": int(time.Since(sc.startedAt).Seconds()),
		}
	}
	c.JSON(http.StatusOK, body)
}

// DebugConfig is the classic forgotten debug route: no authentication, build and feature
// details for anyone who asks.
func (sc *SystemController) DebugConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":     "secman",
		"build":       gin.H{"go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH},
		"environment": "production",
		"features":    gin.H{"legacy_reports": true, "beta_dashboard": false, "debug_routes": true},
	})
}

// TenantFlags returns the feature flags of one tenant. It trusts the id in the path and asks
// for no credentials.
func (sc *SystemController) TenantFlags(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tenant_id": c.Param("tenant_id"),
		"flags":     gin.H{"sso_enforced": false, "export_enabled": true, "audit_log": false},
	})
}
