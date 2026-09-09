package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
	"github.com/grealyve/secman/middlewares"
)

var (
	zapController    = controller.NewZapController()
	reportController = controller.NewReportController()
)

func ZapRoutes(router *gin.Engine) {
	zap := router.Group("/api/v1/zap")
	zap.Use(middlewares.Authentication(), middlewares.Authorization("scanner", "use"))

	// Scan Management
	zap.POST("/abortScan", zapController.ZapPauseScan)
	zap.POST("/deleteScans", zapController.ZapRemoveScan)   // Belki "delete" yetkisi?
	zap.GET("/scans/:scan_id", zapController.ZapGetZapScanStatus)

	// Start scan & List Scans
	zap.POST("/scans", zapController.ZapStartScan) // Belki "create" veya "execute" yetkisi?
	zap.GET("/scans", zapController.ListZapScans)  // Read yetkisi?

	// Alerts
	zap.GET("/alerts/:scan_id", zapController.ZapGetAlerts)             // Read yetkisi?
	zap.GET("/alerts/detail/:alert_id", zapController.ZapGetAlertDetail) // Read yetkisi?

	// Results by URL
	zap.GET("/results", zapController.GetZapScanResultsByURL) // Read yetkisi?
	zap.GET("/findings", zapController.GetAllUserFindings)

	zap.POST("/report", reportController.GenerateZAPReport)
	zap.GET("/reports", reportController.GetZAPReports)
}