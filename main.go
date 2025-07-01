package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/grealyve/lutenix/config"
	"github.com/grealyve/lutenix/controller"
	"github.com/grealyve/lutenix/database"
	"github.com/grealyve/lutenix/logger"
	"github.com/grealyve/lutenix/middlewares"
	"github.com/grealyve/lutenix/routes"
)

func main() {
	config.LoadConfig()
	logger.Log.Println("Configuration loaded successfully")
	authController := controller.NewAuthController()

	// Connect to the database
	dsn := "host=" + config.ConfigInstance.DB_HOST +
		" user=" + config.ConfigInstance.DB_USER +
		" password=" + config.ConfigInstance.DB_PASSWORD +
		" dbname=" + config.ConfigInstance.DB_NAME +
		" port=" + config.ConfigInstance.DB_PORT +
		" sslmode=" + config.ConfigInstance.SSLMode
	database.ConnectDB(dsn)
	logger.Log.Infoln("Database connected successfully")

	// Get Redis URL from environment or use default
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}
	database.ConnectRedis(redisURL)
	logger.Log.Infoln("Redis connection successful")

	router := gin.Default()

	router.Use(gin.Recovery())
	router.Use(middlewares.LoggingMiddleware())
	router.Use(middlewares.CorsMiddleware())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"message":   "SecMan is running",
			"timestamp": "2025-06-30",
		})
	})

	// Serve static files (frontend build)
	router.Static("/static", "./dist/assets")
	router.StaticFile("/", "./dist/index.html")
	router.StaticFile("/favicon.ico", "./dist/favicon.ico")

	// API routes
	routes.AcunetixRoutes(router)
	routes.AdminRoutes(router)
	routes.DashboardRoutes(router)
	routes.SemgrepRoutes(router)
	routes.UserRoutes(router, authController)
	routes.ZapRoutes(router)

	// Catch-all route for SPA (Single Page Application)
	router.NoRoute(func(c *gin.Context) {
		c.File("./dist/index.html")
	})

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "4040"
	}

	logger.Log.Infof("Starting server on port %s", port)
	router.Run("0.0.0.0:" + port)
}
