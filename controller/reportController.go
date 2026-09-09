package controller

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/services"
)

type ReportController struct {
	ReportService *services.ReportService
	UserService   *services.UserService
}

func NewReportController() *ReportController {
	userService := &services.UserService{}
	scanService := &services.ScanService{}
	assetService := &services.AssetService{}
	reportService := services.NewReportService(userService, scanService, assetService)

	return &ReportController{
		ReportService: reportService,
		UserService:   userService,
	}
}

type GenerateZapReportRequest struct {
	Title string   `json:"title" binding:"required"`
	Sites []string `json:"sites" binding:"required"`
}

func (rc *ReportController) GenerateZAPReport(c *gin.Context) {
	logTag := "Controller.GenerateZAPReport"
	logger.Log.Debugf("[%s] Endpoint called", logTag)

	userID := c.MustGet("userID").(uuid.UUID)
	logger.Log.Debugf("[%s] Called for UserID: %s", logTag, userID)

	var request GenerateZapReportRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Log.Errorf("[%s] Invalid request body: %v", logTag, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}
	logger.Log.Debugf("[%s] Request body validated: %+v", logTag, request)

	if len(request.Sites) == 0 {
		logger.Log.Errorf("[%s] No target sites provided", logTag)
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one target site must be provided"})
		return
	}

	_, errUser := rc.UserService.GetUserByID(userID)
	if errUser != nil {
		logger.Log.Warnf("[%s] User not found for ID %s", logTag, userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	reportPath, err := rc.ReportService.GenerateZAPReport(
		userID,
		request.Title,
		request.Sites,
	)

	if err != nil {
		logger.Log.Errorf("[%s] Error calling ReportService.GenerateZAPReport: %v", logTag, err)
		if strings.Contains(err.Error(), "couldn't get ZAP settings") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Could not retrieve ZAP scanner settings for the user."})
		} else if strings.Contains(err.Error(), "ZAP API error") || strings.Contains(err.Error(), "ZAP API failed") {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to generate report via ZAP API: " + err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate ZAP report: " + err.Error()})
		}
		return
	}

	logger.Log.Infof("[%s] ZAP report generated successfully for UserID %s. Path: %s", logTag, userID, reportPath)
	c.JSON(http.StatusOK, gin.H{
		"message":     "ZAP report generation request successful",
		"report_path": reportPath,
	})
}

func (rc *ReportController) GetZAPReports(c *gin.Context) {
	logTag := "Controller.GetZAPReports"
	logger.Log.Debugf("[%s] Endpoint called", logTag)

	userID := c.MustGet("userID").(uuid.UUID)
	logger.Log.Debugf("[%s] Called for UserID: %s", logTag, userID)

	reports, err := rc.ReportService.GetZAPReports(userID)
	if err != nil {
		logger.Log.Errorf("[%s] Error retrieving ZAP reports: %v", logTag, err)

		if strings.Contains(err.Error(), "user not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve ZAP reports: " + err.Error()})
		return
	}

	logger.Log.Infof("[%s] Successfully retrieved %d ZAP reports for UserID %s", logTag, len(reports), userID)
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}
