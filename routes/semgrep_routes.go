package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
	"github.com/grealyve/secman/middlewares"
)

var semgrepController = controller.NewSemgrepController()

func SemgrepRoutes(router *gin.Engine) {
	semgrep := router.Group("/api/v1/semgrep")
	semgrep.Use(middlewares.Authentication(), middlewares.Authorization("scanner", "use"))

	semgrep.GET("/scanDetails", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepScanDetails)
	semgrep.GET("/deployments", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepListDeployments)
	semgrep.GET("/projects", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepListProjects)
	semgrep.GET("/scans", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepListScans)
	semgrep.GET("/findings", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepListFindings)
	semgrep.GET("/secrets", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepListSecrets)
	semgrep.GET("/repository", middlewares.Authorization("scanner", "read"), semgrepController.SemgrepListRepositories)
}
