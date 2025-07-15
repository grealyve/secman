package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/grealyve/lutenix/controller"
	"github.com/grealyve/lutenix/middlewares"
)

var (
	userController = controller.NewUserController()
)

func AdminRoutes(router *gin.Engine) {
	admin := router.Group("/api/v1/admin")

	admin.POST("/register", userController.RegisterUser)

	adminAuthenticated := admin.Use(middlewares.Authentication())
	{
		// adminAuthenticated.DELETE("/deleteUser", middlewares.Authorization("user", "delete"), userController.DeleteUser)
		adminAuthenticated.POST("/createCompany", middlewares.Authorization("admin", "create"), userController.CreateCompany)
		adminAuthenticated.POST("/addCompanyUser", middlewares.Authorization("admin", "update"), userController.AddUserToCompany)
		adminAuthenticated.POST("/makeAdmin", middlewares.Authorization("admin", "update"), userController.MakeAdmin)
		adminAuthenticated.POST("/makeUser", middlewares.Authorization("admin", "update"), userController.MakeUser)
		adminAuthenticated.POST("/deleteUser", middlewares.Authorization("admin", "delete"), userController.DeleteUser)
		adminAuthenticated.GET("/getUsers", middlewares.Authorization("admin", "read"), userController.GetUsers)
		adminAuthenticated.GET("/users/:user_id/profile", middlewares.Authorization("user", "read"), userController.GetUserProfileByID)
		adminAuthenticated.GET("/users/:user_id/scanner-settings", middlewares.Authorization("user", "read"), userController.GetScannerSettingByUserID)
		adminAuthenticated.GET("/companies/:company_id/findings", middlewares.Authorization("user", "read"), userController.GetFindingsByCompanyID)

		// VULNERABLE ENDPOINTS FOR TESTING PURPOSES ONLY
		// These endpoints contain SQL injection vulnerabilities and should not be used in production
		adminAuthenticated.GET("/users/by-email-vuln", middlewares.Authorization("user", "read"), userController.GetUserByEmailV)
		adminAuthenticated.GET("/users/search-vuln", middlewares.Authorization("user", "read"), userController.SearchUsersV)
		adminAuthenticated.GET("/users/filter-vuln", middlewares.Authorization("user", "read"), userController.GetUsersWithFilterV)

		// IDOR VULNERABLE ENDPOINTS FOR TESTING PURPOSES ONLY
		// These endpoints contain IDOR vulnerabilities and should not be used in production
		adminAuthenticated.GET("/users/:user_id/profile-vuln", middlewares.Authorization("user", "read"), userController.GetUserProfileByIDV)
		adminAuthenticated.GET("/users/:user_id/scanner-settings-vuln", middlewares.Authorization("user", "read"), userController.GetScannerSettingByUserIDV)
		adminAuthenticated.GET("/companies/:company_id/findings-vuln", middlewares.Authorization("user", "read"), userController.GetFindingsByCompanyIDV)
	}

}
