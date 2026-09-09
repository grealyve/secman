package controller

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/services"
	"gorm.io/gorm"
)

type ZapController struct {
	UserService  *services.UserService
	AssetService *services.AssetService
}

func NewZapController() *ZapController {
	return &ZapController{
		UserService:  &services.UserService{},
		AssetService: &services.AssetService{},
	}
}

// handleZapRequest is a helper like handleSemgrepRequest, but for ZAP.
func (zc *ZapController) handleZapRequest(c *gin.Context, handler func(userID uuid.UUID) (any, error)) {
	userID := c.MustGet("userID").(uuid.UUID)
	logger.Log.Debugf("handleZapRequest called for user ID: %s", userID)

	_, err := zc.UserService.GetUserByID(userID)
	if err != nil {
		logger.Log.Warnf("User not found for ID %s in handleZapRequest", userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	data, err := handler(userID)
	// Özel Abort durumu kontrolü (ZapGetScanStatus içinden gelebilir)
	if err != nil && err.Error() == "aborting" {
		return
	}
	if err != nil {
		logger.Log.Error("ZAP request failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ZAP operation failed"})
		return
	}

	if data != nil { 
		c.JSON(http.StatusOK, gin.H{"data": data})
	}
}

// ZapStartScan is an alternative to using /scan for starting a scan specifically for ZAP.
func (zc *ZapController) ZapStartScan(c *gin.Context) {
	logger.Log.Debugln("ZapStartScan endpoint called")
	var request struct {
		TargetURL string `json:"target_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Log.Errorln("Invalid request body for ZapStartScan:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Log.Debugf("ZapStartScan request: %+v", request)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		scan, err := zc.AssetService.StartZAPScan(request.TargetURL, userID)
		if err != nil {
			return nil, err
		}
		return gin.H{"scan_id": scan.ID, "zap_spider_scan_id": scan.ZapSpiderScanID, "zap_vuln_scan_id": scan.ZapVulnScanID}, nil
	})
}

func (zc *ZapController) ZapGetScanStatus(c *gin.Context) {
	logger.Log.Debugln("ZapGetScanStatus endpoint called")
	scanIDStr := c.Param("scan_id")
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		logger.Log.Warnf("Invalid scan ID format in ZapGetScanStatus: %s", scanIDStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID format (expected UUID)"})
		return
	}
	logger.Log.Debugf("ZapGetScanStatus called with DB scan ID: %s", scanID)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		status, err := zc.AssetService.CheckZAPScanStatus(scanID, userID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) || err.Error() == "scan not found" {
				logger.Log.Warnf("Scan not found in DB for ID %s in ZapGetScanStatus", scanID)
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Scan not found in database"})
				return nil, fmt.Errorf("aborting")
			}
			return nil, err
		}
		return gin.H{"scan_id": scanID, "status": status}, nil
	})
}

func (zc *ZapController) ZapPauseScan(c *gin.Context) {
	logger.Log.Debugln("ZapPauseScan endpoint called")
	var request struct {
		ScanURL []string `json:"scan_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Log.Errorln("Invalid request body for Pause ZAP scan url:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Log.Debugf("ZapPauseScan called with scan URLs: %s", request.ScanURL)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		result, err := zc.AssetService.PauseZapScan(request.ScanURL, userID)
		if err != nil {
			return nil, err
		}
		return gin.H{"result": result}, nil
	})
}

func (zc *ZapController) ZapRemoveScan(c *gin.Context) {
	logger.Log.Debugln("ZapRemoveScan endpoint called")
	var request struct {
		ScanURL []string `json:"scan_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		logger.Log.Errorln("Invalid request body for Delete ZAP scan url:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Log.Debugf("DeleteScans called with scan URLs: %s", request.ScanURL)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		result, err := zc.AssetService.RemoveZapScan(request.ScanURL, userID)
		if err != nil {
			return nil, err
		}
		return gin.H{"result": result}, nil
	})
}

func (zc *ZapController) ZapGetAlerts(c *gin.Context) {
	logger.Log.Debugln("ZapGetAlerts endpoint called") 
	scanID := c.Param("scan_id")
	logger.Log.Debugf("ZapGetAlerts called with scan ID: %s", scanID)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		alertIDs, err := zc.AssetService.GetZapAlerts(scanID, userID)
		if err != nil {
			return nil, err
		}
		// Veri olarak alert ID'lerini döndür
		return gin.H{"alert_ids": alertIDs}, nil
	})
}

func (zc *ZapController) ZapGetAlertDetail(c *gin.Context) {
	logger.Log.Debugln("ZapGetAlertDetail endpoint called") 
	alertID := c.Param("alert_id")
	logger.Log.Debugf("ZapGetAlertDetail called with alert ID: %s", alertID)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		finding, err := zc.AssetService.GetZapAlertDetail(alertID, userID)
		if err != nil {
			return nil, err
		}
		return finding, nil
	})
}

func (zc *ZapController) ZapGetZapScanStatus(c *gin.Context) {
	logger.Log.Debugln("ZapGetZapScanStatus endpoint called") 
	scanID := c.Param("scan_id")
	logger.Log.Debugf("ZapGetZapScanStatus called with scan ID: %s", scanID)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		result, err := zc.AssetService.GetZapScanStatus(scanID, userID)
		if err != nil {
			return nil, err
		}
		// Veri olarak status bilgisini döndür
		return gin.H{"status": result}, nil
	})
}

func (zc *ZapController) ZapGetZapSpiderStatus(c *gin.Context) {
	logger.Log.Debugln("ZapGetZapSpiderStatus endpoint called")
	scanID := c.Param("scan_id")
	logger.Log.Debugf("ZapGetZapSpiderStatus called with scan ID: %s", scanID)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		result, err := zc.AssetService.GetZapSpiderStatus(scanID, userID)
		if err != nil {
			return nil, err
		}
		return gin.H{"status": result}, nil
	})
}

func (zc *ZapController) ListZapScans(c *gin.Context) {
	logger.Log.Debugln("ListZapScans endpoint called")

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		scanList, err := zc.AssetService.ListZapScansForUser(userID)
		if err != nil {
			logger.Log.Errorf("Error fetching ZAP scan list in controller: %v", err)
			return nil, err
		}
		return gin.H{"scans": scanList}, nil
	})
}

// GetZapScanResultsByURL retrieves the latest completed scan results for a given target URL.
func (zc *ZapController) GetZapScanResultsByURL(c *gin.Context) {
	logger.Log.Debugln("GetZapScanResultsByURL endpoint called")

	targetURL := c.Query("target_url")
	if targetURL == "" {
		logger.Log.Warn("GetZapScanResultsByURL called without target_url query parameter")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'target_url' query parameter"})
		return
	}

	logger.Log.Debugf("GetZapScanResultsByURL called for target URL: %s", targetURL)

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		findings, err := zc.AssetService.FetchAndSaveZapFindingsByURL(targetURL, userID)
		if err != nil {
			if err.Error() == "user not found" {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
				return nil, fmt.Errorf("aborting")
			}
			logger.Log.Errorf("Error in GetScanResultsByURL service call: %v", err)
			return nil, err
		}

		return gin.H{"findings": findings}, nil
	})
}


// GetAllUserFindings handles the request to get all ZAP findings for the logged-in user's company.
func (zc *ZapController) GetAllUserFindings(c *gin.Context) {
	logger.Log.Debugln("GetAllUserFindings endpoint called")

	zc.handleZapRequest(c, func(userID uuid.UUID) (any, error) {
		findings, err := zc.AssetService.GetAllFindingsForUser(userID)
		if err != nil {
			if err.Error() == "user not found" {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User or company context not found"})
				return nil, fmt.Errorf("aborting")
			}
			logger.Log.Errorf("Error fetching all user findings in controller: %v", err)
			return nil, err
		}

		return findings, nil
	})
}