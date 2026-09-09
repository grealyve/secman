package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
	"github.com/grealyve/secman/middlewares"
)

var (
	dashboardController = controller.NewDashboardController()
)

// DashboardRoutes sets up the dashboard related routes
func DashboardRoutes(router *gin.Engine) {
	dashboard := router.Group("/api/v1/dashboard")

	// All dashboard routes require authentication
	dashboardAuthenticated := dashboard.Use(middlewares.Authentication())
	{
		// GET endpoint for dashboard statistics
		dashboardAuthenticated.GET("/stats", dashboardController.GetDashboardStats)
	}
}
