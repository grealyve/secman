package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/secman/logger" // Keep logger if used
	"github.com/grealyve/secman/services"
)

type SemgrepController struct {
	UserService  *services.UserService
	AssetService *services.AssetService
}

func NewSemgrepController() *SemgrepController {
	return &SemgrepController{
		UserService:  &services.UserService{},
		AssetService: &services.AssetService{},
	}
}

// handleSemgrepRequest centralizes user check and error handling for Semgrep endpoints.
func (sc *SemgrepController) handleSemgrepRequest(c *gin.Context, handler func(userID uuid.UUID) (any, error)) {
	userID := c.MustGet("userID").(uuid.UUID)

	_, err := sc.UserService.GetUserByID(userID)
	if err != nil {
		// User check failed.
		logger.Log.Warnf("User not found for ID %s in handleSemgrepRequest", userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	data, err := handler(userID)
	if err != nil {
		// Log Semgrep-specific errors.
		logger.Log.Error("Semgrep request failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Semgrep operation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// SemgrepScanDetails retrieves detailed information about a specific Semgrep scan.
func (sc *SemgrepController) SemgrepScanDetails(c *gin.Context) {
	var request struct {
		ScanID       int    `json:"scan_id" binding:"required"`
		DeploymentID string `json:"deployment_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Log.Errorln("Invalid request body for SemgrepScanDetails:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepGetScanDetails(request.DeploymentID, request.ScanID, userID)
	})
}

// SemgrepListDeployments lists all Semgrep deployments accessible to the user.
func (sc *SemgrepController) SemgrepListDeployments(c *gin.Context) {
	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepListDeployments(userID)
	})
}

// SemgrepListProjects lists Semgrep projects within a specific deployment.
func (sc *SemgrepController) SemgrepListProjects(c *gin.Context) {
	deploymentSlug := c.Query("deployment_slug") // Get from query parameter
	if deploymentSlug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deployment_slug is required"})
		return
	}

	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepListProjects(deploymentSlug, userID)
	})
}

// SemgrepListScans lists Semgrep scans for a specific deployment.
func (sc *SemgrepController) SemgrepListScans(c *gin.Context) {
	deploymentID := c.Query("deployment_id")
	if deploymentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deployment_id is required"})
		return
	}

	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepListScans(deploymentID, userID)
	})
}

// SemgrepListFindings lists Semgrep findings for a specific deployment.
func (sc *SemgrepController) SemgrepListFindings(c *gin.Context) {
	deploymentSlug := c.Query("deployment_slug")
	if deploymentSlug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deployment_slug is required"})
		return
	}

	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepListFindings(deploymentSlug, userID)
	})
}

// SemgrepListSecrets lists Semgrep secret findings for a specific deployment.
func (sc *SemgrepController) SemgrepListSecrets(c *gin.Context) {
	deploymentID := c.Query("deployment_id")
	if deploymentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deployment_id is required"})
		return
	}

	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepListSecrets(deploymentID, userID)
	})
}

// SemgrepListRepositories lists repositories associated with a Semgrep deployment.
func (sc *SemgrepController) SemgrepListRepositories(c *gin.Context) {
	deploymentID := c.Query("deployment_id")
	if deploymentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deployment_id is required"})
		return
	}

	sc.handleSemgrepRequest(c, func(userID uuid.UUID) (any, error) {
		return sc.AssetService.SemgrepListRepositories(deploymentID, userID)
	})
}