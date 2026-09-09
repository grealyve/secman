package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/services"
)

type AcunetixController struct {
	UserService  *services.UserService
	AssetService *services.AssetService
	ReportService *services.ReportService
}

func NewAcunetixController() *AcunetixController {
	return &AcunetixController{
		UserService:  &services.UserService{},
		AssetService: &services.AssetService{},
		ReportService: &services.ReportService{},
	}
}

// handleAcunetixRequest centralizes user check and error handling for Acunetix endpoints.
func (ac *AcunetixController) handleAcunetixRequest(c *gin.Context, handler func(userID uuid.UUID) (any, error)) {
	userID := c.MustGet("userID").(uuid.UUID)

	_, err := ac.UserService.GetUserByID(userID)
	if err != nil {
		// User check failed, necessary for authorization context.
		logger.Log.Warnf("User not found for ID %s in handleAcunetixRequest", userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	data, err := handler(userID)
	if err != nil {
		logger.Log.Error("Acunetix request failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Acunetix operation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": data})
}

// AcunetixGetAllTargets retrieves all registered Acunetix targets for the user.
func (ac *AcunetixController) AcunetixGetAllTargets(c *gin.Context) {
	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		targets, err := ac.AssetService.GetAllAcunetixTargets(userID)
		if err != nil {
			return nil, err
		}

		return targets, nil
	})
}

// AcunetixAddTarget adds a new target to Acunetix.
func (ac *AcunetixController) AcunetixAddTarget(c *gin.Context) {
	var request struct {
		TargetURL string `json:"target_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		ac.AssetService.AddAcunetixTarget(request.TargetURL, userID)
		return gin.H{"message": "Target addition request sent"}, nil
	})
}

// AcunetixGetAllScans fetches and processes all Acunetix scan data for the user.
func (ac *AcunetixController) AcunetixGetAllScans(c *gin.Context) {
	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		scanList, err := ac.AssetService.GetAllAcunetixScan(userID)
		if err != nil {
			return nil, err
		}

		return scanList, nil
	})
}

// AcunetixTriggerScan initiates an Acunetix scan for a specific target.
func (ac *AcunetixController) AcunetixTriggerScan(c *gin.Context) {
	var request struct {
		ScanUrls []string `json:"scan_urls" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		ac.AssetService.TriggerAcunetixScan(request.ScanUrls, userID)
		return gin.H{"message": "Scan triggered"}, nil
	})
}

// AcunetixDeleteTargets requests deletion of specified Acunetix targets.
func (ac *AcunetixController) AcunetixDeleteTargets(c *gin.Context) {
	var request struct {
		TargetUrls []string `json:"target_urls" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		ac.AssetService.DeleteAcunetixTargets(request.TargetUrls, userID)
		return gin.H{"message": "Target deletion request sent"}, nil
	})
}

// AcunetixGetAllVulnerabilities retrieves all Acunetix vulnerabilities.
func (ac *AcunetixController) AcunetixGetAllVulnerabilities(c *gin.Context) {
	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		vulnerabilities, err := ac.AssetService.GetAllVulnerabilitiesAcunetix(userID)
		if err != nil {
			return nil, err
		}

		return vulnerabilities, nil
	})
}

// AcunetixDeleteScans requests deletion of specified Acunetix scans.
func (ac *AcunetixController) AcunetixDeleteScans(c *gin.Context) {
	var request struct {
		ScanUrls []string `json:"scan_urls" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		ac.AssetService.DeleteAcunetixScan(request.ScanUrls, userID)
		return gin.H{"message": "Scan deletion request sent"}, nil
	})
}

// AcunetixAbortScans requests aborting of specified Acunetix scans.
func (ac *AcunetixController) AcunetixAbortScans(c *gin.Context) {
	var request struct {
		ScanUrls []string `json:"scan_urls" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		ac.AssetService.AbortAcunetixScan(request.ScanUrls, userID)
		return gin.H{"message": "Scan abort request sent"}, nil
	})
}

func (ac *AcunetixController) AcunetixGenerateReport(c *gin.Context) {
	var request struct {
		ScanUrls []string `json:"scan_urls" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		ac.ReportService.CreateAcunetixReport(request.ScanUrls, userID)
		return gin.H{"message": "Report generation request sent"}, nil
	})
}

// AcunetixGetAllReports retrieves all Acunetix reports for the user.
func (ac *AcunetixController) AcunetixGetAllReports(c *gin.Context) {
	ac.handleAcunetixRequest(c, func(userID uuid.UUID) (any, error) {
		reports, err := ac.ReportService.GetAcunetixReports(userID)
		if err != nil {
			return nil, err
		}

		return reports, nil
	})
}
