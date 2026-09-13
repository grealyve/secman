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
		// VULN-12: /profile, oturum sahibi yerine token'daki `id` claim'ine göre profil
		// döndürür (GetMyProfile userID'yi token'dan alır) -> id forge edilince subject-
		// confusion BOLA. Authorization("user","read") yalnız role'e bakar, kimliğe değil.
		userAuthenticated.GET("/profile", middlewares.Authorization("user", "read"), userController.GetMyProfile)
		userAuthenticated.POST("/updateProfile", middlewares.Authorization("user", "update"), userController.UpdateProfile)
		userAuthenticated.POST("/updateScanner", middlewares.Authorization("user", "update"), userController.UpdateScannerSetting)

		// MERGE (LTX): eski /api/v1/vuln/{admin,tenant} yüzeyleri gerçekçi /users/ altına
		// taşındı. Yetki/tenant kararları token claim'lerinden (forge edilebilir) alınır;
		// Authorization middleware'i BİLEREK kullanılmaz (kararı handler claim'e göre verir).
		userAuthenticated.GET("/all", userController.GetAllUsersVuln)       // VULN-10 privilege escalation
		userAuthenticated.GET("/tenant", userController.GetTenantUsersVuln) // VULN-13 tenant isolation BOLA
	}
}