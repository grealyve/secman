package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
	"github.com/grealyve/secman/middlewares"
)

var acunetixController = controller.NewAcunetixController()

func AcunetixRoutes(router *gin.Engine) {
	acunetix := router.Group("/api/v1/acunetix")
	acunetix.Use(middlewares.Authentication(), middlewares.Authorization("scanner", "use"))

	acunetix.GET("/targets", acunetixController.AcunetixGetAllTargets)                     // Read yetkisi?
	acunetix.POST("/targets", acunetixController.AcunetixAddTarget)                        // Create/Update yetkisi?
	acunetix.GET("/scans", acunetixController.AcunetixGetAllScans)                         // Read yetkisi?
	acunetix.GET("/vulnerabilities", acunetixController.AcunetixGetAllVulnerabilities)     // Read yetkisi?
	acunetix.POST("/startScan", acunetixController.AcunetixTriggerScan)      // Execute/Update yetkisi?
	acunetix.POST("/targets/delete", acunetixController.AcunetixDeleteTargets)             // Delete yetkisi?
	acunetix.POST("/scans/delete", acunetixController.AcunetixDeleteScans)               // Delete yetkisi?
	acunetix.POST("/scans/abort", acunetixController.AcunetixAbortScans)                // Execute/Update yetkisi?

	
	acunetix.GET("/reports", acunetixController.AcunetixGetAllReports)                   // Read yetkisi?
	acunetix.POST("/generateReport", acunetixController.AcunetixGenerateReport)          // Execute/Update yetkisi?
}