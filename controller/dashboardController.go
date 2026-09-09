package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/services"
)

type DashboardController struct {
	DashboardService *services.DashboardService
	UserService      *services.UserService
}

func NewDashboardController() *DashboardController {
	return &DashboardController{
		DashboardService: services.NewDashboardService(),
		UserService:      &services.UserService{},
	}
}

// GetDashboardStats handles the request to get dashboard statistics
func (dc *DashboardController) GetDashboardStats(c *gin.Context) {
	logger.Log.Debugln("GetDashboardStats endpoint called")
	
	// Get user ID from the context (set by authentication middleware)
	userIDValue, exists := c.Get("userID")
	if !exists {
		logger.Log.Errorln("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	
	userID, ok := userIDValue.(uuid.UUID)
	if !ok {
		logger.Log.Errorln("Invalid user ID format in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Get user details to retrieve company ID
	user, err := dc.UserService.GetUserByID(userID)
	if err != nil {
		logger.Log.Errorln("Failed to get user details:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user details"})
		return
	}

	// Get company ID from user
	companyID := user.CompanyID

	logger.Log.Debugf("Getting dashboard stats for user ID: %s, company ID: %s", userID, companyID)

	// Get total scan count
	totalScans, err := dc.DashboardService.GetTotalScans(companyID)
	if err != nil {
		logger.Log.Errorln("Failed to get total scan count:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get total scan count"})
		return
	}

	// Get scan count by scanner type
	scansByType, err := dc.DashboardService.GetScansByType(companyID)
	if err != nil {
		logger.Log.Errorln("Failed to get scans by type:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scans by type"})
		return
	}

	// Get scan count by status
	scansByStatus, err := dc.DashboardService.GetScansByStatus(companyID)
	if err != nil {
		logger.Log.Errorln("Failed to get scans by status:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scans by status"})
		return
	}

	// Get total vulnerability count
	totalVulnerabilities, err := dc.DashboardService.GetTotalVulnerabilities(companyID)
	if err != nil {
		logger.Log.Errorln("Failed to get total vulnerability count:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get total vulnerability count"})
		return
	}

	// Get recent scans (limit to 5)
	recentScans, err := dc.DashboardService.GetRecentScans(companyID, 5)
	if err != nil {
		logger.Log.Errorln("Failed to get recent scans:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get recent scans"})
		return
	}

	// Get findings distribution by severity
	findingsBySeverity, err := dc.DashboardService.GetFindingsBySeverity(companyID)
	if err != nil {
		logger.Log.Errorln("Failed to get findings by severity:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get findings by severity"})
		return
	}

	// Return all statistics
	logger.Log.Infoln("Successfully retrieved dashboard statistics for user:", userID)
	c.JSON(http.StatusOK, gin.H{
		"total_scans":           totalScans,
		"scans_by_type":         scansByType,
		"scans_by_status":       scansByStatus,
		"total_vulnerabilities": totalVulnerabilities,
		"recent_scans":          recentScans,
		"findings_by_severity":  findingsBySeverity,
	})
}
