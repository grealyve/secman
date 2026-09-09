package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/models"
	"github.com/grealyve/secman/utils"
)

var (
	reportsResponseModel = models.ReportsResponsePage{}
	groupNameReportIdMap = make(map[string]models.ReportResponse)
	reportPathPrefix     = "./reports/"
)

const template_id = "11111111-1111-1111-1111-111111111126"

type ReportService struct {
	AssetService *AssetService
	UserService  *UserService
	ScanService  *ScanService
}

func NewReportService(userService *UserService, scanService *ScanService, assetService *AssetService) *ReportService {
	return &ReportService{
		UserService:  userService,
		ScanService:  scanService,
		AssetService: assetService,
	}
}

func (r *ReportService) GetAcunetixReports(userID uuid.UUID) (models.AcunetixReports, error) {
	var reportsResponseModel models.AcunetixReports

	cursor := ""

	for {
		endpoint := "/api/v1/reports?l=99"
		if cursor != "" {
			endpoint += "&c=" + cursor
		}
		resp, err := utils.SendGETRequestAcunetix(endpoint, userID)
		if err != nil {
			logger.Log.Errorln("Request error:", err)
			return models.AcunetixReports{}, err
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			logger.Log.Errorln(string(body))
			logger.Log.Errorln("Response Status:", resp.Status)
		}

		json.Unmarshal(body, &reportsResponseModel)

		if len(reportsResponseModel.Pagination.Cursors) > 1 {
			nextCursorIndex := 1
			nextCursor := reportsResponseModel.Pagination.Cursors[nextCursorIndex]
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
	acunetixSetting, err := utils.AcunetixGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Acunetix setting couldn't fetch:", err)
		return reportsResponseModel, err
	}
	
	var updatedReports []struct {
		Download       []string  `json:"download"`
		GenerationDate time.Time `json:"generation_date"`
		ReportID       string    `json:"report_id"`
		Source         struct {
			ListType    string   `json:"list_type"`
			Description string   `json:"description"`
			IDList      []string `json:"id_list"`
		} `json:"source"`
		Status       string `json:"status"`
		TemplateID   string `json:"template_id"`
		TemplateName string `json:"template_name"`
		TemplateType int    `json:"template_type"`
	}
	
	for _, report := range reportsResponseModel.Reports {
		downloadLink := acunetixSetting.ScannerURL + ":" + strconv.Itoa(acunetixSetting.ScannerPort) + "/api/v1/reports/" + report.ReportID
		report.Download = []string{downloadLink}
		updatedReports = append(updatedReports, report)
	}
	
	reportsResponseModel.Reports = updatedReports
	
	return reportsResponseModel, nil
}

// Create a report for a list of scans
func (r *ReportService) CreateAcunetixReport(targetSlice []string, userID uuid.UUID) {
	r.AssetService.GetAllAcunetixScan(userID)
	var scannedIDs []string

	for _, url := range targetSlice {
		scanModel, ok := scansJsonMap[url]
		if !ok {
			logger.Log.Infof("Scan URL %s not found in map", url)
			continue
		}
		scannedIDs = append(scannedIDs, scanModel.ScanID)
	}

	creatingReportModel := models.GenerateReport{
		TemplateID: template_id,
		Source: models.Source{
			ListType: "scans",
			IDList:   scannedIDs,
		},
	}

	reportJSON, err := json.Marshal(creatingReportModel)
	if err != nil {
		logger.Log.Errorln("JSON encoding error:", err)
		return
	}

	resp, err := utils.SendCustomRequestAcunetix("POST", "/api/v1/reports", reportJSON, userID)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log.Errorln("Error reading response body:", err)
		return
	}

	if resp.StatusCode == 201 {
		logger.Log.Infoln("Report has been created successfully")
	} else {
		logger.Log.Errorln("Response Body:", string(body))
		return
	}
}

/*
Report Generate ZAP
/JSON/reports/action/generate/?apikey=6f1ebonoa9980csb8ls2895rl0&title=test&template=modern&theme=&description=&contexts=&sites=http://secman.com|http://hedef.com&sections=&includedConfidences=&includedRisks=&reportFileName=&reportFileNamePattern=&reportDir=&display=

Result:
{
	"generate":"C:\\Users\\Grealyve\\2025-04-13-ZAP-Report-secman.com.html"
}
*/

func (r *ReportService) GenerateZAPReport(userID uuid.UUID, title string, targetSites []string) (string, error) {
	logTag := "GenerateZAPReport"
	logger.Log.Debugf("[%s] Called for UserID: %s, Title: %s, Sites: %v", logTag, userID, title, targetSites)

	joinedSites := strings.Join(targetSites, "|")
	logger.Log.Debugf("[%s] Joined sites: %s", logTag, joinedSites)

	scannerSetting, err := r.AssetService.getUserScannerZAPSettings(userID)
	if err != nil {
		logger.Log.Errorf("[%s] Error getting ZAP settings for UserID %s: %v", logTag, userID, err)
		return "", fmt.Errorf("couldn't get ZAP settings: %w", err)
	}
	logger.Log.Debugf("[%s] ZAP settings retrieved: URL=%s, Port=%d", logTag, scannerSetting.ScannerURL, scannerSetting.ScannerPort)

	queryParams := url.Values{}
	queryParams.Add("apikey", scannerSetting.APIKey)
	queryParams.Add("title", title)
	queryParams.Add("template", "modern")
	queryParams.Add("sites", joinedSites)
	queryParams.Add("display", "true")
	queryParams.Add("reportFileName", title)

	endpointPath := "/JSON/reports/action/generate/"
	fullURL := fmt.Sprintf("%s:%d%s", scannerSetting.ScannerURL, scannerSetting.ScannerPort, endpointPath)
	encodedQuery := queryParams.Encode()

	logger.Log.Debugf("[%s] Sending ZAP report generation request to: %s with query: %s", logTag, fullURL, encodedQuery)
	requestPathWithQuery := fmt.Sprintf("%s?%s", endpointPath, encodedQuery)

	resp, err := utils.SendGETRequestZap(requestPathWithQuery, scannerSetting.APIKey, scannerSetting.ScannerURL, scannerSetting.ScannerPort)
	if err != nil {
		logger.Log.Errorf("[%s] Error creating HTTP request: %v", logTag, err)
		return "", fmt.Errorf("failed to create report request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log.Errorf("[%s] Error reading ZAP response body: %v", logTag, err)
		return "", fmt.Errorf("failed to read ZAP response: %w", err)
	}
	logger.Log.Debugf("[%s] ZAP Response Status: %s, Body: %s", logTag, resp.Status, string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		logger.Log.Errorf("[%s] ZAP API returned non-OK status: %s", logTag, resp.Status)
		return "", fmt.Errorf("ZAP API failed with status %s", resp.Status)
	}

	var result struct {
		Generate string `json:"generate"`
	}

	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		logger.Log.Errorf("[%s] Error decoding ZAP generate report response: %v", logTag, err)
		return "", fmt.Errorf("failed to decode ZAP response: %w", err)
	}

	if result.Generate == "" {
		logger.Log.Warnf("[%s] ZAP response decoded successfully, but 'generate' field is empty.", logTag)
		return "", fmt.Errorf("ZAP did not return a report path")
	}

	logger.Log.Infof("[%s] ZAP report generated successfully at: %s", logTag, result.Generate)

	// Get the user to find their company ID
	user, err := r.UserService.GetUserByID(userID)
	if err != nil {
		logger.Log.Warnf("[%s] Error getting user for UserID %s: %v - Cannot save report to database", logTag, userID, err)
		return result.Generate, nil
	}

	// Save report to database
	report := models.Report{
		Name:         title,
		CompanyID:    user.CompanyID,
		DownloadLink: result.Generate,
		ReportType:   "ZAP",
	}

	if err := database.DB.Create(&report).Error; err != nil {
		logger.Log.Warnf("[%s] Error saving report to database: %v - Report generated but not saved", logTag, err)
		return result.Generate, nil
	}

	logger.Log.Infof("[%s] Report saved to database with ID: %s", logTag, report.ID)
	return result.Generate, nil
}

func (r *ReportService) GetZAPReports(userID uuid.UUID) ([]models.Report, error) {
	logTag := "GetZAPReports"
	logger.Log.Debugf("[%s] Getting ZAP reports for user ID: %s", logTag, userID)

	// Get the user to find their company ID
	user, err := r.UserService.GetUserByID(userID)
	if err != nil {
		logger.Log.Errorf("[%s] Error getting user for UserID %s: %v", logTag, userID, err)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	var reports []models.Report
	if err := database.DB.Where("company_id = ? AND report_type = ?", user.CompanyID, "ZAP").Find(&reports).Error; err != nil {
		logger.Log.Errorf("[%s] Error retrieving ZAP reports: %v", logTag, err)
		return nil, fmt.Errorf("failed to retrieve ZAP reports: %w", err)
	}

	logger.Log.Infof("[%s] Successfully retrieved %d ZAP reports for user %s", logTag, len(reports), userID)
	return reports, nil
}
