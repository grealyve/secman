package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/controller"
	"github.com/grealyve/secman/middlewares"
)


func UserRoutes(router *gin.Engine, authController *controller.AuthController) {
	user := router.Group("/api/v1/users")

	user.POST("/login", authController.Login)

	userAuthenticated := user.Use(middlewares.Authentication())
	{
		userAuthenticated.GET("/logout", middlewares.Authorization("user", "logout"), authController.Logout)
		userAuthenticated.GET("/profile", middlewares.Authorization("user", "read"), userController.GetMyProfile)
		userAuthenticated.POST("/updateProfile", middlewares.Authorization("user", "update"), userController.UpdateProfile)
		userAuthenticated.POST("/updateScanner", middlewares.Authorization("user", "update"), userController.UpdateScannerSetting)
	}
}