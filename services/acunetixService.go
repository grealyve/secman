package services

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/models"
	"github.com/grealyve/secman/utils"
	"gorm.io/gorm"
)

var (
	triggerModel = models.TriggerScan{
		ProfileID: "11111111-1111-1111-1111-111111111111",
		Schedule: models.Schedule{
			Disable:       false,
			StartDate:     nil,
			TimeSensitive: false,
		},
		TargetID:    "",
		Incremental: false,
	}

	//Target ID - Scan ID
	targetIdScanIdMap = make(map[string]string)
	//Target ID - Scan Model
	scansJsonMap = make(map[string]models.ScanJSONModel)

	//Scan URL - Severity
	scanUrlSeverityMap = make(map[string]SeverityCounts)

	//Asset URL - Target ID
	assetUrlTargetIdMap = make(map[string]string)
)

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Info     int `json:"info"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
}

// Fetches Target data from the Acunetix server.
func (a *AssetService) GetAllAcunetixTargets(userID uuid.UUID) (models.AcunetixTargets, error) {
	logger.Log.Debugf("GetAllAcunetixTargets called for user ID: %s", userID)
	cursor := ""
	var acunetixTargets models.AcunetixTargets

	for {
		endpoint := "/api/v1/targets?l=100"  // Using limit of 100 for more efficient retrieval
		if cursor != "" {
			endpoint += "&c=" + cursor
		}
		logger.Log.Debugf("Fetching Acunetix targets with endpoint: %s", endpoint)

		resp, err := utils.SendGETRequestAcunetix(endpoint, userID)
		if err != nil {
			logger.Log.Errorln("Request error:", err)
			return models.AcunetixTargets{}, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Log.Errorln("Error reading response body:", err)
			return models.AcunetixTargets{}, err
		}

		var response models.Response
		err = json.Unmarshal(body, &response)
		if err != nil {
			logger.Log.Errorln("Error unmarshalling response:", err)
			return models.AcunetixTargets{}, err
		}
		
		var pageTargets models.AcunetixTargets
		err = json.Unmarshal(body, &pageTargets)
		if err != nil {
			logger.Log.Errorln("Error unmarshalling targets:", err)
			return models.AcunetixTargets{}, err
		}
		
		acunetixTargets.Targets = append(acunetixTargets.Targets, pageTargets.Targets...)
		
		for _, target := range response.Targets {
			logger.Log.Debugf("Acunetix target found: Address=%s, TargetID=%s", target.Address, target.TargetID)
			assetUrlTargetIdMap[target.Address] = target.TargetID
		}

		if len(response.Pagination.Cursors) > 1 {
			nextCursorIndex := 1
			nextCursor := response.Pagination.Cursors[nextCursorIndex]
			if nextCursor == "" {
				logger.Log.Debugln("No more Acunetix targets to fetch (empty cursor).")
				break
			}
			
			cursor = nextCursor
			logger.Log.Debugf("Next cursor for Acunetix targets: %s", cursor)
		} else {
			logger.Log.Debugln("No pagination cursors found or no more pages.")
			break
		}
	}

	logger.Log.Infof("Successfully fetched all Acunetix targets for user ID: %s. Total targets: %d", userID, len(acunetixTargets.Targets))
	return acunetixTargets, nil
}

func (a *AssetService) AddAcunetixTarget(targetURL string, userID uuid.UUID) {
	logger.Log.Debugf("AddAcunetixTarget called for target URL: %s, user ID: %s", targetURL, userID) // Debug: Entry Point

	target := models.Target{
		Address:     targetURL,
		Description: "",
		Type:        "default",
		Criticality: 10,
	}

	targetJSON, err := json.Marshal(target)
	if err != nil {
		logger.Log.Errorln("Json encoding error:", err)
		return
	}

	responseAddTarget, err := utils.SendCustomRequestAcunetix("POST", "/api/v1/targets", targetJSON, userID)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return
	}
	defer responseAddTarget.Body.Close()

	if responseAddTarget.StatusCode != 201 {
		logger.Log.Errorf("Failed to add Acunetix target. Status: %s, Target URL: %s", responseAddTarget.Status, targetURL)
	} else {
		logger.Log.Infof("Successfully added Acunetix target: %s", targetURL)
	}

}

func (a *AssetService) GetAllAcunetixScan(userID uuid.UUID) (models.AllScans, error) {
	logger.Log.Debugf("GetAllAcunetixScan called for user ID: %s", userID) // Debug: Entry Point
	cursor := ""
	var allScans models.AllScans

	for {
		endpoint := "/api/v1/scans?l=99"
		if cursor != "" {
			endpoint += "&c=" + cursor
		}
		logger.Log.Debugf("Fetching Acunetix scans with endpoint: %s", endpoint)

		resp, err := utils.SendGETRequestAcunetix(endpoint, userID)
		if err != nil {
			logger.Log.Errorln("Error fetching Acunetix scans:", err)
			return models.AllScans{}, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Log.Errorln("Error reading Acunetix scan response body:", err)
			return models.AllScans{}, err
		}

		err = json.Unmarshal(body, &allScans)
		if err != nil {
			logger.Log.Errorln("Error unmarshalling Acunetix scan response:", err)
			return models.AllScans{}, err
		}

		for _, scan := range allScans.Scans {
			logger.Log.Debugf("Acunetix scan found: Target Address=%s, ScanID=%s, Status=%s", scan.Target.Address, scan.ScanID, scan.CurrentSession.Status)

			scansJsonMap[scan.Target.Address] = models.ScanJSONModel{
				TargetID:  scan.TargetID,
				Status:    scan.CurrentSession.Status,
				Address:   scan.Target.Address,
				ScanID:    scan.ScanID,
				StartDate: scan.CurrentSession.StartDate,
			}
			targetIdScanIdMap[scan.TargetID] = scan.ScanID
			logger.Log.Debugf("Mapping TargetID %s to ScanID %s", scan.TargetID, scan.ScanID)
			scanUrlSeverityMap[scan.Target.Address] = scan.CurrentSession.SeverityCounts
		}

		if len(allScans.Pagination.Cursors) > 1 {
			nextCursorIndex := 1
			nextCursor := allScans.Pagination.Cursors[nextCursorIndex]
			if nextCursor == "" {
				logger.Log.Debugln("No more Acunetix scans to fetch (empty cursor).")
				break
			}
			
			cursor = nextCursor
			logger.Log.Debugf("Next cursor for Acunetix scans: %s", cursor)
		} else {
			logger.Log.Debugln("No pagination cursors found or no more pages.")
			break
		}
	}
	logger.Log.Infof("Successfully fetched Acunetix scan data for user ID: %s", userID)
	return allScans, nil
}

// Scan başlatma fonksiyonu
func (a *AssetService) TriggerAcunetixScan(scanUrls []string, userID uuid.UUID) {
	logger.Log.Debugf("TriggerAcunetixScan called for target ID: %s, user ID: %s", scanUrls, userID)
	_, err := a.GetAllAcunetixTargets(userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Acunetix targets:", err)
		return
	}

	for _, scanUrl := range scanUrls {
		triggerModel.TargetID = assetUrlTargetIdMap[scanUrl]

		triggerJSON, err := json.Marshal(triggerModel)
		if err != nil {
			logger.Log.Errorln("JSON encoding error:", err)
			return
		}

		resp, err := utils.SendCustomRequestAcunetix("POST", "/api/v1/scans", triggerJSON, userID)
		if err != nil {
			logger.Log.Errorln("Error triggering Acunetix scan:", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Log.Errorln("Error reading response body:", err)
			return
		}

		if resp.StatusCode == 201 {
			logger.Log.Infof("Scan started successfully for target URL: %s", scanUrls)
		} else {
			logger.Log.Errorf("Trigger Scan Response Status: %s, Body: %s", resp.Status, string(body))
		}

	}
}

// Hedefin daha önce taranıp taranmadığını kontrol eder.
func (a *AssetService) IsScannedTargetAcunetix(targetID string, userID uuid.UUID) bool {
	logger.Log.Debugf("IsScannedTargetAcunetix called for target ID: %s, user ID: %s", targetID, userID)
	var scan models.Scan
	err := DB.Where("target_id = ? AND scanner = ? AND status IN (?)",
		targetID,
		"acunetix",
		[]string{models.ScanStatusCompleted, models.ScanStatusProcessing}).
		First(&scan).Error

	if err == nil {
		logger.Log.Infof("Target ID %s has been scanned before.", targetID)
		return true
	} else if err == gorm.ErrRecordNotFound {
		logger.Log.Infof("Target ID %s has not been scanned before.", targetID)
		return false
	} else {
		logger.Log.Errorf("Error checking if target %s is scanned: %v", targetID, err)
		return false
	}
}

func (a *AssetService) DeleteAcunetixTargets(targetUrlList []string, userID uuid.UUID) error {
	logger.Log.Debugf("DeleteAcunetixTargets called for targets: %v, user ID: %s", targetUrlList, userID)
	var targetIDList []string

	_, err := a.GetAllAcunetixTargets(userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Acunetix targets:", err)
		return err
	}

	for _, targetUrl := range targetUrlList {
		targetID, ok := assetUrlTargetIdMap[targetUrl]
		if !ok {
			logger.Log.Infof("Target URL %s not found in map", targetUrl)
			continue
		}
		targetIDList = append(targetIDList, targetID)
	}

	targetJSON, err := json.Marshal(models.DeleteTargets{TargetIDList: targetIDList})
	if err != nil {
		logger.Log.Errorln("JSON encoding error:", err)
		return err
	}

	resp, err := utils.SendCustomRequestAcunetix("POST", "/api/v1/targets/delete", targetJSON, userID)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log.Errorf("Error reading response body: %v", err)
		return err
	}

	if resp.StatusCode == 204 {
		logger.Log.Infoln("Targets deleted successfully")
	} else {
		logger.Log.Errorf("Failed to delete Acunetix targets.  Status: %s, Response Body: %s", resp.Status, string(body))
		return fmt.Errorf("failed to delete Acunetix targets: %s", string(body))
	}

	return nil
}

func (as *AssetService) GetAllTargetsAcunetix(userID uuid.UUID) (map[string]string, error) {
	logger.Log.Debugln("GetAllTargetsAcunetix called")
	notScannedTargets := make(map[string]string)
	assetUrlTargetIdMap := make(map[string]string)

	acunetixTargets, err := as.GetAllAcunetixTargets(userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Acunetix targets:", err)
		return nil, fmt.Errorf("data couldn't fetch from database: %v", err)
	}

	for _, target := range acunetixTargets.Targets {
		assetUrlTargetIdMap[target.Address] = target.TargetID
	}

	var scans []models.Scan
	if err := DB.Where(
		"scanner = ? AND status IN (?)",
		"acunetix",
		[]string{
			models.ScanStatusCompleted,
			models.ScanStatusProcessing,
			models.ScanStatusPending,
		},
	).Find(&scans).Error; err != nil {
		logger.Log.Errorln("Error fetching scans from database:", err)
		return nil, fmt.Errorf("data couldn't fetch from database: %v", err)
	}
	logger.Log.Debugf("Fetched %d scans from database", len(scans))

	scannedTargets := make(map[string]bool)
	for _, scan := range scans {
		logger.Log.Debugf("Marking target URL %s as scanned", scan.TargetURL)
		scannedTargets[scan.TargetURL] = true
	}

	for url, targetID := range assetUrlTargetIdMap {
		if !scannedTargets[url] {
			logger.Log.Debugf("Target URL %s (ID: %s) is not scanned", url, targetID)
			notScannedTargets[url] = targetID
		}
	}
	logger.Log.Infof("Found %d unscanned Acunetix targets", len(notScannedTargets))
	return notScannedTargets, nil
}

func (as *AssetService) GetAllVulnerabilitiesAcunetix(userID uuid.UUID) (models.AcunetixVulnerabilities, error) {
	logger.Log.Debugln("GetAllVulnerabilitiesAcunetix called")
	var vulnerabilities models.AcunetixVulnerabilities
	cursor := ""

	for {
		endpoint := "/api/v1/vulnerabilities?l=99&q=status:!ignored;status:!fixed;"
		if cursor != "" {
			endpoint += "&c=" + cursor
		}

		resp, err := utils.SendGETRequestAcunetix(endpoint, userID)
		if err != nil {
			logger.Log.Errorln("Error fetching Acunetix vulnerabilities:", err)
			return models.AcunetixVulnerabilities{}, fmt.Errorf("data couldn't fetch from database: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Log.Errorln("Error reading response body:", err)
			return models.AcunetixVulnerabilities{}, fmt.Errorf("data couldn't fetch from database: %v", err)
		}

		err = json.Unmarshal(body, &vulnerabilities)
		if err != nil {
			logger.Log.Errorln("Error unmarshalling Acunetix vulnerabilities:", err)
			return models.AcunetixVulnerabilities{}, fmt.Errorf("data couldn't fetch from database: %v", err)
		}

		if len(vulnerabilities.Pagination.Cursors) > 1 {
			nextCursorIndex := 1
			nextCursor := vulnerabilities.Pagination.Cursors[nextCursorIndex]
			if nextCursor == "" {
				logger.Log.Debugln("No more Acunetix vulnerabilities to fetch (empty cursor).")
				break
			}
			
			cursor = nextCursor
			logger.Log.Debugf("Next cursor for Acunetix scans: %s", cursor)
		} else {
			logger.Log.Debugln("No pagination cursors found or no more pages.")
			break
		}
	}

	return vulnerabilities, nil
}

// DELETE /api/v1/scans/{scanID}
func (as *AssetService) DeleteAcunetixScan(scanUrl []string, userID uuid.UUID) {
	as.GetAllAcunetixScan(userID)
	logger.Log.Infof("DeleteAcunetixScan called for scan URLs: %v, user ID: %s", scanUrl, userID)

	for _, url := range scanUrl {
		var scanModel models.ScanJSONModel
		scanModel, ok := scansJsonMap[url]
		if !ok {
			logger.Log.Infof("Scan URL %s not found in map", url)
			continue
		}

		resp, err := utils.SendCustomRequestAcunetix("DELETE", "/api/v1/scans/"+scanModel.ScanID, nil, userID)
		if err != nil {
			logger.Log.Errorln("Request error:", err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 204 {
			logger.Log.Errorln(string(body))
			logger.Log.Errorln("Response Status:", resp.Status)
		}
	}
}

// POST /api/v1/scans/{scanID}/abort
func (as *AssetService) AbortAcunetixScan(scanUrl []string, userID uuid.UUID) {
	as.GetAllAcunetixScan(userID)
	logger.Log.Infof("AbortAcunetixScan called for scan URLs: %v, user ID: %s", scanUrl, userID)

	for _, url := range scanUrl {
		var scanModel models.ScanJSONModel
		scanModel, ok := scansJsonMap[url]
		if !ok {
			logger.Log.Infof("Scan URL %s not found in map", url)
			continue
		}

		resp, err := utils.SendCustomRequestAcunetix("POST", "/api/v1/scans/"+scanModel.ScanID+"/abort", nil, userID)
		if err != nil {
			logger.Log.Errorln("Request error:", err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 204 {
			logger.Log.Errorln(string(body))
			logger.Log.Errorln("Response Status:", resp.Status)
		}
	}
}
