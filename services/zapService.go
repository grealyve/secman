package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/models"
	"github.com/grealyve/secman/utils"
	"gorm.io/gorm"
)

type ZapApiScanDetail struct {
	ReqCount      string `json:"reqCount"`
	AlertCount    string `json:"alertCount"`
	Progress      string `json:"progress"`
	NewAlertCount string `json:"newAlertCount"`
	ID            string `json:"id"`
	State         string `json:"state"`
}

type ZapApiScansResponse struct {
	Scans []ZapApiScanDetail `json:"scans"`
}

// ZapAlertDetail mirrors the structure of a single alert from the ZAP /core/view/alerts endpoint
type ZapAlertDetail struct {
	SourceID    string            `json:"sourceid"`
	Other       string            `json:"other"`
	Method      string            `json:"method"`
	Evidence    string            `json:"evidence"`
	PluginID    string            `json:"pluginId"`
	CWEID       string            `json:"cweid"`
	Confidence  string            `json:"confidence"`
	WASCID      string            `json:"wascid"`
	Description string            `json:"description"`
	MessageID   string            `json:"messageId"`
	URL         string            `json:"url"`
	Reference   string            `json:"reference"`
	Solution    string            `json:"solution"`
	Alert       string            `json:"alert"` 
	Param       string            `json:"param"`
	Attack      string            `json:"attack"`
	Name        string            `json:"name"` 
	Risk        string            `json:"risk"` 
	ID          string            `json:"id"`   
	AlertRef    string            `json:"alertRef"`
	Tags        map[string]string `json:"tags"` 
}

// ZapAlertsResponse mirrors the top-level structure of the ZAP /core/view/alerts response
type ZapAlertsResponse struct {
	Alerts []ZapAlertDetail `json:"alerts"`
}

// Helper function: Get ZAP scanner settings for the user
func (a *AssetService) getUserScannerZAPSettings(userID uuid.UUID) (*models.ScannerSetting, error) {
	logger.Log.Debugf("getUserScannerZAPSettings called for user ID: %s", userID)  
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("User not found for ID %s: %v", userID, err)
		return nil, fmt.Errorf("user couldn't find: %v", err)
	}

	var scannerSetting models.ScannerSetting
	if err := database.DB.Where("company_id = ? AND scanner = ?", user.CompanyID, "zap").First(&scannerSetting).Error; err != nil {
		logger.Log.Errorf("Scanner settings (ZAP) not found for company ID %s: %v", user.CompanyID, err)
		return nil, fmt.Errorf("scanner settings couldn't find: %v", err)
	}

	logger.Log.Debugf("Retrieved ZAP scanner settings for user ID: %s", userID)
	return &scannerSetting, nil
}

func (a *AssetService) AddZapSpiderURL(url string, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("AddZapSpiderURL called for URL: %s, user ID: %s", url, userID)  

	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("/JSON/spider/action/scan/?apikey=%s&url=%s&maxChildren=&recurse=1&contextName=&subtreeOnly=",
		scannerSetting.APIKey,
		url)

	logger.Log.Debugf("Sending ZAP spider request to: %s", endpoint)

	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorln("Error sending ZAP spider request:", err)
		return "", fmt.Errorf("spider scan couldn't start: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Scan string `json:"scan"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Log.Errorln("Error decoding ZAP spider response:", err)
		return "", fmt.Errorf("spider response couldn't handle: %v", err)
	}

	logger.Log.Infof("ZAP spider scan started. Scan ID: %s", result.Scan)
	return result.Scan, nil
}

func (a *AssetService) AddZapScanURL(url string, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("AddZapScanURL called for URL: %s, user ID: %s", url, userID)  
	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("/JSON/ascan/action/scan/?apikey=%s&url=%s&recurse=1&inScopeOnly=&scanPolicyName=&method=&postData=&contextId=",
		scannerSetting.APIKey,
		url)

	logger.Log.Debugf("Sending ZAP active scan request to: %s", endpoint)
	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorln("Error sending ZAP active scan request:", err)
		return "", fmt.Errorf("vulnerability scan couldn't start: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Scan string `json:"scan"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Log.Errorln("Error decoding ZAP active scan response:", err)
		return "", fmt.Errorf("scan response couldn't handle: %v", err)
	}

	logger.Log.Infof("ZAP active scan started. Scan ID: %s", result.Scan)
	return result.Scan, nil
}

func (a *AssetService) GetZapScanStatus(scanID string, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("GetZapScanStatus called for scan ID: %s, user ID: %s", scanID, userID)  
	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return "", err    
	}

	endpoint := fmt.Sprintf("/JSON/ascan/view/status/?apikey=%s&scanId=%s", scannerSetting.APIKey, scanID)
	logger.Log.Debugf("Checking ZAP scan status at: %s", endpoint)

	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorln("Error getting ZAP scan status:", err)
		return "", fmt.Errorf("scan status couldn't get: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Log.Errorln("Error decoding ZAP scan status response:", err)
		return "", fmt.Errorf("status response couldn't handle: %v", err)
	}
	logger.Log.Infof("ZAP scan status for scan ID %s: %s", scanID, result.Status)
	return result.Status, nil
}

func (a *AssetService) GetZapAlerts(scanID string, userID uuid.UUID) ([]string, error) {
	logger.Log.Debugf("GetZapAlerts called for scan ID: %s, user ID: %s", scanID, userID)  

	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return nil, err    
	}

	endpoint := fmt.Sprintf("/JSON/ascan/view/alertsIds/?apikey=%s&scanId=%s",
		scannerSetting.APIKey,
		scanID)

	logger.Log.Debugf("Fetching ZAP alert IDs from: %s", endpoint)
	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorln("Error fetching ZAP alert IDs:", err)
		return nil, fmt.Errorf("alerts couldn't get: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		AlertsIds []string `json:"alertsIds"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Log.Errorln("Error decoding ZAP alert IDs response:", err)
		return nil, fmt.Errorf("alerts response couldn't handle: %v", err)
	}

	logger.Log.Infof("Found %d alert IDs for ZAP scan ID %s", len(result.AlertsIds), scanID)
	return result.AlertsIds, nil
}

func (a *AssetService) GetZapAlertDetail(alertID string, userID uuid.UUID) (models.Finding, error) {
	logger.Log.Debugf("GetZapAlertDetail called for alert ID: %s, user ID: %s", alertID, userID)  
	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return models.Finding{}, err    
	}

	endpoint := fmt.Sprintf("/JSON/alert/view/alert/?apikey=%s&id=%s",
		scannerSetting.APIKey,
		alertID)

	logger.Log.Debugf("Fetching ZAP alert detail from: %s", endpoint)
	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorln("Error fetching ZAP alert detail:", err)
		return models.Finding{}, fmt.Errorf("alert detail couldn't get: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Alert struct {
			URL         string `json:"url"`
			Risk        string `json:"risk"`
			Name        string `json:"name"`
			Evidence    string `json:"evidence"`
			Severity    string `json:"severity"`
			CWE         string `json:"cweid"`
			Description string `json:"description"`
		} `json:"alert"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Log.Errorln("Error decoding ZAP alert detail response:", err)
		return models.Finding{}, fmt.Errorf("alert detail response couldn't handle: %v", err)
	}

	finding := models.Finding{
		URL:               result.Alert.URL,
		Risk:              result.Alert.Risk,
		VulnerabilityName: result.Alert.Name,
		Location:          result.Alert.CWE,
	}
	logger.Log.Infof("Retrieved ZAP alert detail for alert ID %s: %+v", alertID, finding) 
	return finding, nil
}

func (a *AssetService) RemoveZapScan(scanUrls []string, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("RemoveZapScan called for scan URLs: %v, user ID: %s", scanUrls, userID) 
	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return "", err    
	}

	var user models.User
	if err := database.DB.Select("company_id").First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("Error fetching user %s: %v", userID, err)
		return "", fmt.Errorf("user not found: %v", err)
	}
	
	var scans []models.Scan
	if err := database.DB.Where("company_id = ? AND target_url IN ? AND scanner = 'zap'", user.CompanyID, scanUrls).Find(&scans).Error; err != nil {
		logger.Log.Errorf("Error fetching scans for URLs %v: %v", scanUrls, err)
		return "", fmt.Errorf("error retrieving scans: %v", err)
	}

	if len(scans) == 0 {
		logger.Log.Warnf("No scans found for URLs: %v", scanUrls)
		return "No scans found to delete", nil
	}

	var lastResult string
	tx := database.DB.Begin()
	if tx.Error != nil {
		logger.Log.Errorln("Error starting transaction:", tx.Error)
		return "", fmt.Errorf("database transaction couldn't start: %v", tx.Error)
	}

	for _, scan := range scans {
		if scan.ZapVulnScanID != "" {
			endpoint := fmt.Sprintf("/JSON/spider/action/removeScan/?apikey=%s&scanId=%s",
				scannerSetting.APIKey,
				scan.ZapVulnScanID)

			logger.Log.Debugf("Sending ZAP scan removal request to: %s", endpoint)

			resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
			if err != nil {
				logger.Log.Errorln("Error sending ZAP scan removal request:", err)
			} else {
				var result struct {
					Result string `json:"Result"`
				}

				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					logger.Log.Errorln("Error decoding ZAP scan removal response:", err)
				} else {
					lastResult = result.Result
					logger.Log.Infof("ZAP scan removal result for scan ID %s: %s", scan.ZapVulnScanID, result.Result)
				}
				resp.Body.Close()
			}
		} else {
			logger.Log.Warnf("Scan ID %s has no ZAP vulnerability scan ID. Skipping ZAP API call.", scan.ID)
		}

		if err := tx.Where("scan_id = ?", scan.ID).Delete(&models.Finding{}).Error; err != nil {
			logger.Log.Errorln("Error deleting findings for scan:", err)
			tx.Rollback()
			return "", fmt.Errorf("error deleting findings: %v", err)
		}
		
		if err := tx.Delete(&scan).Error; err != nil {
			logger.Log.Errorln("Error deleting scan from database:", err)
			tx.Rollback()
			return "", fmt.Errorf("error deleting scan from database: %v", err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		logger.Log.Errorln("Error committing transaction:", err)
		return "", fmt.Errorf("database transaction failed: %v", err)
	}

	if lastResult == "" {
		return "Scans deleted successfully", nil
	}
	return lastResult, nil
}

func (a *AssetService) PauseZapScan(scanUrls []string, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("PauseZapScan called for scan URLs: %v, user ID: %s", scanUrls, userID)  
	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return "", err
	}

	var user models.User
	if err := database.DB.Select("company_id").First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("Error fetching user %s: %v", userID, err)
		return "", fmt.Errorf("user not found: %v", err)
	}
	
	var scans []models.Scan
	if err := database.DB.Where("company_id = ? AND target_url IN ? AND scanner = 'zap'", user.CompanyID, scanUrls).Find(&scans).Error; err != nil {
		logger.Log.Errorf("Error fetching scans for URLs %v: %v", scanUrls, err)
		return "", fmt.Errorf("error retrieving scans: %v", err)
	}

	if len(scans) == 0 {
		logger.Log.Warnf("No scans found for URLs: %v", scanUrls)
		return "No scans found to pause", nil
	}

	var lastResult string
	for _, scan := range scans {
		if scan.ZapVulnScanID != "" {
			endpoint := fmt.Sprintf("/JSON/ascan/action/pause/?apikey=%s&scanId=%s",
				scannerSetting.APIKey,
				scan.ZapVulnScanID)

			logger.Log.Debugf("Sending ZAP scan pause request to: %s", endpoint)
			resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
			if err != nil {
				logger.Log.Errorln("Error sending ZAP scan pause request:", err)
				continue
			}

			var result struct {
				Result string `json:"Result"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				logger.Log.Errorln("Error decoding ZAP scan pause response:", err)
				resp.Body.Close()
				continue
			}
			resp.Body.Close()

			lastResult = result.Result
			logger.Log.Infof("ZAP scan pause result for scan ID %s: %s", scan.ZapVulnScanID, result.Result)
			
			// Update scan status in database
			scan.Status = models.ScanStatusPaused
			if err := database.DB.Save(&scan).Error; err != nil {
				logger.Log.Errorln("Error updating scan status in database:", err)
			}
		} else {
			logger.Log.Warnf("Scan ID %s has no ZAP vulnerability scan ID. Skipping ZAP API call.", scan.ID)
		}
	}

	if lastResult == "" {
		return "Scans paused successfully", nil
	}
	return lastResult, nil
}

func (a *AssetService) StartZAPScan(url string, userID uuid.UUID) (*models.Scan, error) {
	logger.Log.Debugf("StartZAPScan called for URL: %s, user ID: %s", url, userID)  

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("User not found for ID %s: %v", userID, err)
		return nil, fmt.Errorf("user not found: %v", err)
	}

	scan := &models.Scan{
		CompanyID: user.CompanyID,
		CreatedBy: userID,
		Scanner:   "zap",
		TargetURL: url,
		Status:    models.ScanStatusProcessing,
	}

	if err := database.DB.Create(scan).Error; err != nil {
		logger.Log.Errorln("Error creating scan record:", err)
		return nil, fmt.Errorf("couldn't create scan record: %v", err)
	}
	logger.Log.Infof("Created scan record for URL: %s, Scan ID: %s", url, scan.ID)

	spiderScanID, err := a.AddZapSpiderURL(url, userID)
	if err != nil {
		scan.Status = models.ScanStatusFailed
		database.DB.Save(scan)
		logger.Log.Errorf("Failed to start ZAP spider scan for URL: %s, Scan ID: %s", url, scan.ID)
		return nil, err    
	}
	logger.Log.Infof("Started ZAP spider scan for URL: %s, Spider Scan ID: %s", url, spiderScanID)

	// Wait for spider scan to complete
	for {
		status, err := a.GetZapSpiderStatus(spiderScanID, userID)
		if err != nil {
			scan.Status = models.ScanStatusFailed
			database.DB.Save(scan)
			logger.Log.Errorf("Failed to get ZAP spider status for URL: %s, Scan ID: %s", url, scan.ID)
			return nil, err    
		}
		logger.Log.Debugf("ZAP spider scan status for URL: %s, Scan ID: %s, Status: %s", url, scan.ID, status)

		if status == "100" {
			logger.Log.Infof("ZAP spider scan completed for URL: %s, Scan ID: %s", url, scan.ID)
			break
		}
		logger.Log.Debugf("Waiting for ZAP spider scan to complete.  Sleeping for 5 seconds...")
		time.Sleep(5 * time.Second)
	}

	// Start vulnerability scan
	vulnScanID, err := a.AddZapScanURL(url, userID)
	if err != nil {
		scan.Status = models.ScanStatusFailed
		database.DB.Save(scan)
		logger.Log.Errorf("Failed to start ZAP vulnerability scan for URL: %s, Scan ID: %s", url, scan.ID)
		return nil, err    
	}
	logger.Log.Infof("Started ZAP vulnerability scan for URL: %s, Vulnerability Scan ID: %s", url, vulnScanID)

	// Store scan IDs in database
	scan.ZapSpiderScanID = spiderScanID
	scan.ZapVulnScanID = vulnScanID
	if err := database.DB.Save(scan).Error; err != nil {
		logger.Log.Errorf("Error updating scan record with scan IDs for URL: %s, Scan ID: %s", url, scan.ID)
		return nil, fmt.Errorf("couldn't update scan record: %v", err)
	}
	logger.Log.Infof("Updated scan record with ZAP scan IDs for URL: %s, Scan ID: %s", url, scan.ID)

	return scan, nil
}

// GetZapSpiderStatus gets the status of a ZAP spider scan
func (a *AssetService) GetZapSpiderStatus(spiderScanID string, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("GetZapSpiderStatus called for spider scan ID: %s, user ID: %s", spiderScanID, userID)

	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("/JSON/spider/view/status/?apikey=%s&scanId=%s", scannerSetting.APIKey, spiderScanID)
	logger.Log.Debugf("Checking ZAP spider status at: %s", endpoint)

	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorln("Error getting ZAP spider scan status:", err)
		return "", fmt.Errorf("spider status couldn't get: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Log.Errorln("Error decoding ZAP spider status response:", err)
		return "", fmt.Errorf("status response couldn't handle: %v", err)
	}

	logger.Log.Infof("ZAP spider scan status for scan ID %s: %s", spiderScanID, result.Status)
	return result.Status, nil
}

// CheckScanStatus checks the current status of a scan
func (a *AssetService) CheckZAPScanStatus(scanID uuid.UUID, userID uuid.UUID) (string, error) {
	logger.Log.Debugf("CheckZAPScanStatus called for scan ID: %s, user ID: %s", scanID, userID)
	var scan models.Scan

	if err := database.DB.First(&scan, "id = ?", scanID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("scan not found")
		}
		logger.Log.Errorf("Error fetching scan %s: %v", scanID, err)
		return "", fmt.Errorf("database error finding scan: %v", err)
	}

	if scan.Status == models.ScanStatusCompleted || scan.Status == models.ScanStatusFailed {
		logger.Log.Infof("Scan %s already in terminal state: %s. No action needed.", scanID, scan.Status)
		return scan.Status, nil
	}

	if scan.Status != models.ScanStatusProcessing {
		logger.Log.Warnf("Scan %s is in unexpected state '%s'. Returning current status.", scanID, scan.Status)
		return scan.Status, nil
	}

	if scan.ZapVulnScanID == "" {
		logger.Log.Errorf("Scan %s is processing but has no ZapVulnScanID. Failing scan.", scanID)
		scan.Status = models.ScanStatusFailed
		if err := database.DB.Save(&scan).Error; err != nil {
			logger.Log.Errorf("Failed to save scan %s status to Failed (missing ZapID): %v", scanID, err)
			return models.ScanStatusFailed, fmt.Errorf("missing ZAP scan ID and failed to update status: %v", err)
		}
		return models.ScanStatusFailed, fmt.Errorf("missing ZAP vulnerability scan ID")
	}

	zapStatus, err := a.GetZapScanStatus(scan.ZapVulnScanID, userID)
	if err != nil {
		logger.Log.Errorf("Error checking ZAP active scan status for scan %s (ZAP ID: %s): %v", scan.ID, scan.ZapVulnScanID, err)
		return scan.Status, err
	}
	logger.Log.Infof("ZAP active scan status for DB scan ID %s (ZAP ID %s): %s", scan.ID, scan.ZapVulnScanID, zapStatus)

	if zapStatus == "100" && scan.Status == models.ScanStatusProcessing {
		logger.Log.Infof("ZAP active scan completed for scan ID %s and DB status is Processing. Fetching and saving results...", scan.ID)

		savedFindings, processErr := a.FetchAndSaveZapFindingsByURL(scan.TargetURL, userID)
		if processErr != nil {
			logger.Log.Errorf("Error fetching/saving results for scan ID %s: %v. Failing scan.", scan.ID, processErr)
			scan.Status = models.ScanStatusFailed
			scan.VulnerabilityCount = 0
			if err := database.DB.Save(&scan).Error; err != nil {
				logger.Log.Errorf("Failed to save scan %s status to Failed after processing error: %v", scanID, err)
				return models.ScanStatusFailed, fmt.Errorf("processing error (%v) and failed to update status (%v)", processErr, err)
			}
			return models.ScanStatusFailed, processErr
		}

		logger.Log.Infof("Successfully processed results for scan %s. Updating status to Completed.", scan.ID)
		scan.Status = models.ScanStatusCompleted
		scan.VulnerabilityCount = len(savedFindings)
		logger.Log.Debugf("Attempting to save Scan %s with Status: %s, VulnCount: %d", scan.ID, scan.Status, scan.VulnerabilityCount)
		if err := database.DB.Save(&scan).Error; err != nil {
			logger.Log.Errorf("CRITICAL: Findings saved for scan %s, but FAILED to update scan status/count to Completed: %v", scan.ID, err)
			return models.ScanStatusCompleted, fmt.Errorf("findings saved, but failed to update scan status: %v", err)
		}
		logger.Log.Infof("Successfully updated scan %s status to %s with %d vulnerabilities.", scan.ID, scan.Status, scan.VulnerabilityCount)

	} else if zapStatus != "100" {
		logger.Log.Debugf("ZAP scan %s (ZAP ID %s) is still running (%s%%). DB status (%s) remains unchanged.", scan.ID, scan.ZapVulnScanID, zapStatus, scan.Status)
	} else {
		logger.Log.Debugf("ZAP scan %s (ZAP ID %s) is at 100%%, but DB status is already '%s'. No action needed.", scan.ID, scan.ZapVulnScanID, scan.Status)
	}

	return scan.Status, nil
}

// FetchAndSaveZapFindingsByURL fetches ZAP findings for a given URL and saves them to the database
func (a *AssetService) FetchAndSaveZapFindingsByURL(baseURL string, userID uuid.UUID) ([]models.Finding, error) {
	logger.Log.Debugf("FetchAndSaveZapFindingsByURL called for baseURL: %s, user ID: %s", baseURL, userID)

	var user models.User
	if err := database.DB.Select("company_id").First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		logger.Log.Errorf("Error fetching user %s: %v", userID, err)
		return nil, fmt.Errorf("could not retrieve user information: %v", err)
	}

	var latestScan models.Scan
	err := database.DB.Where("company_id = ? AND target_url = ? AND scanner = ?",
		user.CompanyID, baseURL, "zap",
	).Order("created_at DESC").First(&latestScan).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("no scan record found for the specified URL in the database")
		}
		logger.Log.Errorf("Error finding latest scan for URL %s, company %s: %v", baseURL, user.CompanyID, err)
		return nil, fmt.Errorf("database error finding scan record: %v", err)
	}
	logger.Log.Infof("Found associated scan record ID: %s for URL: %s", latestScan.ID, baseURL)

	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		return nil, err
	}
	encodedBaseURL := url.QueryEscape(baseURL)
	endpoint := fmt.Sprintf("/JSON/core/view/alerts/?apikey=%s&baseurl=%s&start=&count=",
		scannerSetting.APIKey, encodedBaseURL)

	logger.Log.Debugf("Fetching ZAP alerts from: %s", endpoint)
	resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		return nil, fmt.Errorf("alerts couldn't be fetched from ZAP: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read alerts response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ZAP get alerts API returned non-OK status: %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}
	var zapResult ZapAlertsResponse
	if err := json.Unmarshal(bodyBytes, &zapResult); err != nil {
		return nil, fmt.Errorf("ZAP alerts response couldn't be handled: %v", err)
	}
	logger.Log.Infof("Successfully fetched %d alerts from ZAP for base URL: %s", len(zapResult.Alerts), baseURL)

	savedFindings := []models.Finding{}

	tx := database.DB.Begin()
	if tx.Error != nil {
		logger.Log.Errorf("Failed to begin transaction for scan %s: %v", latestScan.ID, tx.Error)
		return nil, fmt.Errorf("database transaction could not start: %v", tx.Error)
	}

	logger.Log.Debugf("Deleting existing findings for scan ID: %s", latestScan.ID)
	if err := tx.Where("scan_id = ?", latestScan.ID).Delete(&models.Finding{}).Error; err != nil {
		tx.Rollback()
		logger.Log.Errorf("Failed to delete existing findings for scan %s: %v", latestScan.ID, err)
		return nil, fmt.Errorf("failed to clear previous findings: %v", err)
	}
	logger.Log.Infof("Successfully deleted existing findings for scan %s", latestScan.ID)

	for _, zapAlert := range zapResult.Alerts {
		finding := models.Finding{
			ScanID:            latestScan.ID,
			URL:               zapAlert.URL,
			Risk:              zapAlert.Risk,
			VulnerabilityName: zapAlert.Alert,
			Location:          zapAlert.URL,
		}

		if err := tx.Create(&finding).Error; err != nil {
			tx.Rollback()
			logger.Log.Errorf("Error saving finding (Vuln: %s) within transaction for scan %s: %v", finding.VulnerabilityName, latestScan.ID, err)
			// Tek bir hata bile tüm işlemi başarısız kılar (Transaction mantığı)
			return nil, fmt.Errorf("failed to save finding '%s' during transaction: %v", finding.VulnerabilityName, err)
		}
		savedFindings = append(savedFindings, finding)
	}

	if err := tx.Commit().Error; err != nil {
		logger.Log.Errorf("Failed to commit transaction for scan %s: %v", latestScan.ID, err)
		return nil, fmt.Errorf("database transaction could not commit: %v", err)
	}

	logger.Log.Infof("Transaction committed. Processed %d ZAP alerts, saved %d findings for scan %s.", len(zapResult.Alerts), len(savedFindings), latestScan.ID)

	return savedFindings, nil
}

func (a *AssetService) ListZapScansForUser(userID uuid.UUID) ([]models.Scan, error) {
	logger.Log.Debugf("ListZapScansForUser called for user ID: %s", userID)

	var user models.User
	if err := database.DB.Select("company_id").First(&user, "id = ?", userID).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Log.Warnf("User not found for ID %s in ListZapScansForUser", userID)
			return nil, fmt.Errorf("user not found")
		}
		logger.Log.Errorf("Error fetching user %s for ListZapScansForUser: %v", userID, err)
		return nil, fmt.Errorf("database error fetching user: %v", err)
	}
	companyID := user.CompanyID
	if companyID == uuid.Nil {
		logger.Log.Errorf("User %s has a nil CompanyID", userID)
		return nil, fmt.Errorf("user is not associated with a company")
	}
	logger.Log.Debugf("Fetching ZAP scans for company ID: %s", companyID)

	var dbScans []models.Scan 
	err := database.DB.Where("company_id = ? AND scanner = ?", companyID, "zap").
		Order("created_at DESC").
		Find(&dbScans).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Log.Errorf("Error fetching ZAP scans from database for company %s: %v", companyID, err)
		return nil, fmt.Errorf("database error fetching scans: %v", err)
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Log.Infof("No ZAP scans found for company ID: %s", companyID)
		return []models.Scan{}, nil
	}

	logger.Log.Debugf("Found %d ZAP scans in DB for company ID: %s", len(dbScans), companyID)

	scannerSetting, err := a.getUserScannerZAPSettings(userID)
	if err != nil {
		logger.Log.Warnf("Could not get ZAP scanner settings for user %s: %v. Proceeding without live statuses.", userID, err)
		scannerSetting = nil
	}

	zapStatusMap := make(map[string]ZapApiScanDetail)
	if scannerSetting != nil {
		endpoint := fmt.Sprintf("/JSON/ascan/view/scans/?apikey=%s", scannerSetting.APIKey)
		logger.Log.Debugf("Fetching live ZAP scan statuses from: %s", endpoint)

		resp, err := utils.SendGETRequestZap(endpoint, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
		if err != nil {
			logger.Log.Warnf("Failed to fetch live ZAP statuses: %v. Proceeding with DB statuses.", err)
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var zapApiResponse ZapApiScansResponse
				if err := json.NewDecoder(resp.Body).Decode(&zapApiResponse); err != nil {
					logger.Log.Warnf("Failed to decode live ZAP statuses response: %v. Proceeding with DB statuses.", err)
				} else {
					for _, zapScan := range zapApiResponse.Scans {
						zapStatusMap[zapScan.ID] = zapScan
					}
					logger.Log.Infof("Successfully fetched %d live scan statuses from ZAP.", len(zapStatusMap))
				}
			} else {
				bodyBytes, _ := io.ReadAll(resp.Body)
				logger.Log.Warnf("ZAP API /ascan/view/scans returned non-OK status: %d. Body: %s. Proceeding with DB statuses.", resp.StatusCode, string(bodyBytes))
			}
		}
	} else {
		logger.Log.Debugln("Skipping live ZAP status fetch because scanner settings are unavailable.")
	}

	for i := range dbScans {
		scan := &dbScans[i]

		scan.Progress = nil

		if scan.ZapVulnScanID != "" {
			if zapDetail, found := zapStatusMap[scan.ZapVulnScanID]; found {
				progressVal, err := strconv.Atoi(zapDetail.Progress)
				if err != nil {
					logger.Log.Warnf("Could not parse progress '%s' for ZAP scan ID %s: %v", zapDetail.Progress, zapDetail.ID, err)
				}

				isTerminalDB := scan.Status == models.ScanStatusCompleted || scan.Status == models.ScanStatusFailed

				var liveStatus string
				mappedStatus, ok := models.ScanStatusMap[zapDetail.State]
				if ok {
					liveStatus = mappedStatus
				} else {
					logger.Log.Warnf("Unmapped ZAP state '%s' encountered for ZAP scan %s", zapDetail.State, zapDetail.ID)
					liveStatus = zapDetail.State 
				}

				if !isTerminalDB {
					scan.Status = liveStatus
					if err == nil {
						scan.Progress = &progressVal
					}
					logger.Log.Tracef("Updated scan %s (ZAP ID %s) with live status: %s (%d%%)", scan.ID, scan.ZapVulnScanID, scan.Status, progressVal)

				} else {
					logger.Log.Tracef("Live ZAP status for scan %s (ZAP ID %s) is %s, but DB status is terminal (%s). Keeping DB status.", scan.ID, scan.ZapVulnScanID, liveStatus, scan.Status)
				}
			} else {
				logger.Log.Tracef("Scan %s (ZAP ID %s) not found in live ZAP status response. Using DB status: %s", scan.ID, scan.ZapVulnScanID, scan.Status)
			}
		} else {
			logger.Log.Tracef("Scan %s has no ZAP Vuln Scan ID. Using DB status: %s", scan.ID, scan.Status)
		}
	}

	logger.Log.Infof("Successfully prepared %d ZAP scans for user %s (company %s) with potentially merged statuses.", len(dbScans), userID, companyID)
	return dbScans, nil
}

// GetAllFindingsForUser retrieves all findings for all ZAP scans belonging to the user's company.
func (a *AssetService) GetAllFindingsForUser(userID uuid.UUID) ([]models.Finding, error) {
	logger.Log.Debugf("GetAllFindingsForUser called for user ID: %s", userID)

	var user models.User
	if err := database.DB.Select("company_id").First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Log.Warnf("User not found for ID %s in GetAllFindingsForUser", userID)
			return nil, fmt.Errorf("user not found")
		}
		logger.Log.Errorf("Error fetching user %s for GetAllFindingsForUser: %v", userID, err)
		return nil, fmt.Errorf("database error fetching user: %v", err)
	}
	companyID := user.CompanyID
	if companyID == uuid.Nil {
		logger.Log.Errorf("User %s has a nil CompanyID", userID)
		return nil, fmt.Errorf("user is not associated with a company")
	}
	logger.Log.Debugf("Fetching all ZAP findings for company ID: %s", companyID)

	var findings []models.Finding

	err := database.DB.Joins("Scan").
					Where(`"Scan"."company_id" = ? AND "Scan"."scanner" = ?`, companyID, "zap").
					Order("findings.created_at DESC").
					Preload("Scan").
					Find(&findings).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Log.Infof("No ZAP findings found for company ID: %s", companyID)
			return []models.Finding{}, nil
		}

		logger.Log.Errorf("Error fetching ZAP findings from database for company %s: %v", companyID, err) 
		return nil, fmt.Errorf("database error fetching findings: %v", err)
	}

	logger.Log.Infof("Successfully fetched %d ZAP findings for company ID: %s", len(findings), companyID)
	return findings, nil
}