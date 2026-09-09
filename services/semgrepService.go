package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/models"
	"github.com/grealyve/secman/utils"
	"gorm.io/gorm"
)

// Lists semgrep deployments
func (a *AssetService) SemgrepListDeployments(userID uuid.UUID) ([]models.SemgrepDeployment, error) {
	logger.Log.Debugf("SemgrepListDeployments called for user ID: %s", userID)  

	resp, err := utils.SendGETRequestSemgrep("/api/v1/deployments", userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Semgrep deployments:", err)
		return nil, fmt.Errorf("deployments couldn't fetch: %v", err)
	}
	defer resp.Body.Close()

	var response struct {
		Deployments []models.SemgrepDeployment `json:"deployments"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		logger.Log.Errorln("Error decoding Semgrep deployments response:", err)
		return nil, fmt.Errorf("deployment response couldn't handle: %v", err)
	}
	logger.Log.Infof("Retrieved %d Semgrep deployments for user ID: %s", len(response.Deployments), userID)

	return response.Deployments, nil
}

// Lists semgrep projects
func (a *AssetService) SemgrepListProjects(deploymentSlug string, userID uuid.UUID) ([]models.SemgrepProject, error) {
	logger.Log.Debugf("SemgrepListProjects called for deployment slug: %s, user ID: %s", deploymentSlug, userID)  
	endpoint := fmt.Sprintf("/api/v1/deployments/%s/projects", deploymentSlug)
	resp, err := utils.SendGETRequestSemgrep(endpoint, userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Semgrep projects:", err)
		return nil, fmt.Errorf("projeler couldn't fetch: %v", err)
	}
	defer resp.Body.Close()

	var response struct {
		Projects []models.SemgrepProject `json:"projects"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		logger.Log.Errorln("Error decoding Semgrep projects response:", err)
		return nil, fmt.Errorf("project response couldn't handle: %v", err)
	}
	logger.Log.Infof("Retrieved %d Semgrep projects for deployment slug: %s", len(response.Projects), deploymentSlug)

	return response.Projects, nil
}

// Fetches scan details from the Semgrep server
func (a *AssetService) SemgrepGetScanDetails(deploymentID string, scanID int, userID uuid.UUID) (*models.SemgrepScan, error) {
	usr, err := utils.SemgrepGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Error fetching user settings:", err)
		return nil, fmt.Errorf("user settings couldn't fetch: %v", err)
	}

	logger.Log.Debugf("SemgrepGetScanDetails called for deployment ID: %s, scan ID: %d, user ID: %s, company ID: %s", deploymentID, scanID, userID, usr.CompanyID)  
	endpoint := fmt.Sprintf("/api/v1/deployments/%s/scan/%d", deploymentID, scanID)

	if usr.CompanyID == uuid.Nil {
		logger.Log.Errorf("Attempted to save Semgrep scan with nil CompanyID for deployment %s, scan %d", deploymentID, scanID)
		return nil, fmt.Errorf("invalid company ID provided for saving scan")
	}

	resp, err := utils.SendGETRequestSemgrep(endpoint, userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Semgrep scan details:", err)
		return nil, fmt.Errorf("scan details couldn't fetch: %v", err)
	}
	defer resp.Body.Close()

	var scan models.SemgrepScan
	if err := json.NewDecoder(resp.Body).Decode(&scan); err != nil {
		logger.Log.Errorln("Error decoding Semgrep scan details response:", err)
		return nil, fmt.Errorf("scan response couldn't handle: %v", err)
	}

	dbScan := models.Scan{
		Scanner:            "semgrep",
		Status:             models.ScanStatusCompleted,
		TargetURL:          scan.Meta.RepoURL,
		VulnerabilityCount: scan.Stats.Findings,
		CompanyID:          usr.CompanyID,
		CreatedBy:          userID,
	}
	if err := database.DB.Create(&dbScan).Error; err != nil {
		logger.Log.Errorln("Error saving Semgrep scan to database:", err)
		return nil, fmt.Errorf("semgrep scan couldn't save: %w", err)
	}

	logger.Log.Infof("Retrieved and saved Semgrep scan details for deployment ID: %s, scan ID: %d, DB Scan ID: %s", deploymentID, scanID, dbScan.ID)

	return &scan, nil
}

// Lists semgrep scans
func (a *AssetService) SemgrepListScans(deploymentID string, user_id uuid.UUID) ([]models.SemgrepScan, error) {
	logger.Log.Debugf("SemgrepListScans called for deployment ID: %s, user ID: %s", deploymentID, user_id)
	param := models.SemgrepScanSearchParams{}

	body, err := json.Marshal(param)
	if err != nil {
		logger.Log.Errorln("Error encoding Semgrep scan search parameters:", err)
		return nil, fmt.Errorf("scan search parameters couldn't encode: %v", err)
	}

	resp, err := utils.SendCustomRequestSemgrep("POST", "/api/v1/deployments/"+deploymentID+"/scans/search", body, user_id)
	if err != nil {
		logger.Log.Errorln("Error sending Semgrep scan search request:", err)
		return nil, fmt.Errorf("scan search parameters couldn't encode: %v", err) // Same error message as above, this seems correct.
	}
	defer resp.Body.Close()

	var response struct {
		Scans []models.SemgrepScan `json:"scans"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		logger.Log.Errorln("Error decoding Semgrep scan search response:", err)
		return nil, fmt.Errorf("scan response couldn't handle: %v", err)
	}
	logger.Log.Infof("Retrieved %d Semgrep scans for deployment ID: %s", len(response.Scans), deploymentID)
	return response.Scans, nil
}

// Lists semgrep findings
func (a *AssetService) SemgrepListFindings(deploymentSlug string, userID uuid.UUID) ([]models.Finding, error) {
	logger.Log.Debugf("SemgrepListFindings called for deployment slug: %s, user ID: %s", deploymentSlug, userID)

	var user models.User
	if err := database.DB.Select("company_id").First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Log.Errorf("User not found for ID: %s", userID)
			return nil, fmt.Errorf("user not found: %w", err)
		}
		logger.Log.Errorf("Error fetching user's company ID: %v", err)
		return nil, fmt.Errorf("failed to retrieve user details: %w", err)
	}
	if user.CompanyID == uuid.Nil {
		logger.Log.Errorf("User %s does not have a valid CompanyID associated.", userID)
		return nil, fmt.Errorf("user %s has no associated company", userID)
	}
	companyID := user.CompanyID
	logger.Log.Debugf("Found CompanyID: %s for UserID: %s", companyID, userID)

	endpoint := fmt.Sprintf("/api/v1/deployments/%s/findings", deploymentSlug)
	resp, err := utils.SendGETRequestSemgrep(endpoint, userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Semgrep findings initially:", err)
		return nil, fmt.Errorf("initial findings fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Log.Errorf("Semgrep API returned non-OK status %d during initial findings fetch. Body: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("semgrep API request failed with status %d", resp.StatusCode)
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		logger.Log.Errorf("Could not read response body from initial findings fetch: %v", readErr)
		return nil, fmt.Errorf("failed to read semgrep response body: %w", readErr)
	}

	var apiResponse struct {
		Findings []struct {
			Repository struct {
				URL string `json:"url"`
			} `json:"repository"`
			Severity string `json:"severity"`
			RuleName string `json:"rule_name"`
			Location struct {
				FilePath string `json:"file_path"`
				Line     int    `json:"line"`
			} `json:"location"`
		} `json:"findings"`
	}

	if err := json.Unmarshal(bodyBytes, &apiResponse); err != nil {
		logger.Log.Errorf("Error decoding Semgrep findings response: %v", err)
		logger.Log.Debugf("Raw Semgrep findings response body: %s", string(bodyBytes))
		return nil, fmt.Errorf("finding response couldn't handle: %w", err)
	}
	logger.Log.Debugf("Successfully decoded %d findings from Semgrep API for deployment: %s", len(apiResponse.Findings), deploymentSlug)

	var targetURLForScan string
	if len(apiResponse.Findings) > 0 && apiResponse.Findings[0].Repository.URL != "" {
		targetURLForScan = apiResponse.Findings[0].Repository.URL
		logger.Log.Debugf("Using Repository URL '%s' as TargetURL for Scan record.", targetURLForScan)
	} else {
		targetURLForScan = deploymentSlug
		logger.Log.Warnf("No findings returned or first finding lacks Repository URL. Using deploymentSlug '%s' as TargetURL for Scan record.", targetURLForScan)
	}

	scan := models.Scan{}

	queryConditions := models.Scan{
		CompanyID: companyID,
		Scanner:   "semgrep",
		TargetURL: targetURLForScan,
	}
	attrsToCreate := models.Scan{
		CreatedBy: userID,
	}
	assignAttrs := models.Scan{
		Status:         models.ScanStatusProcessing,
		DeploymentSlug: deploymentSlug,
	}

	err = database.DB.Where(queryConditions).
		Attrs(attrsToCreate).
		Assign(assignAttrs).
		FirstOrCreate(&scan).Error

	if err != nil {
		logger.Log.Errorf("Error finding or creating Scan record for TargetURL %s (derived from deployment %s): %v", targetURLForScan, deploymentSlug, err)
		if scan.ID != uuid.Nil {
			database.DB.Model(&scan).Update("Status", models.ScanStatusFailed)
		}
		return nil, fmt.Errorf("failed to prepare scan record: %w", err)
	}
	logger.Log.Infof("Using Scan record ID: %s for TargetURL: %s (DeploymentSlug: %s)", scan.ID, targetURLForScan, scan.DeploymentSlug)

	var savedFindings []models.Finding

	err = database.DB.Transaction(func(tx *gorm.DB) error {
		logger.Log.Debugf("Deleting existing findings for ScanID: %s before inserting new ones.", scan.ID)
		if errDel := tx.Where("scan_id = ?", scan.ID).Delete(&models.Finding{}).Error; errDel != nil {
			logger.Log.Errorf("Failed to delete previous findings for ScanID %s: %v", scan.ID, errDel)
			return fmt.Errorf("failed to clear previous findings: %w", errDel)
		}

		if len(apiResponse.Findings) > 0 {
			logger.Log.Debugf("Inserting %d new findings for ScanID: %s", len(apiResponse.Findings), scan.ID)
			for _, f := range apiResponse.Findings {
				findingSeverity := f.Severity
				if findingSeverity == "" {
					logger.Log.Warnf("Semgrep finding (Rule: '%s', Path: '%s', ScanID: %s) has empty severity. Defaulting to 'UNKNOWN'.", f.RuleName, f.Location.FilePath, scan.ID)
					findingSeverity = "UNKNOWN"
				}

				if f.Repository.URL != targetURLForScan {
					logger.Log.Warnf("Finding's Repository URL ('%s') differs from Scan's TargetURL ('%s') for ScanID %s. Finding will still be associated.", f.Repository.URL, targetURLForScan, scan.ID)
				}

				if f.Repository.URL == "" || f.RuleName == "" {
					logger.Log.Warnf("Semgrep finding missing required data (URL or RuleName) for ScanID %s. Skipping.", scan.ID)
					continue
				}

				finding := models.Finding{
					ScanID:            scan.ID,
					URL:               f.Repository.URL,
					Risk:              findingSeverity,
					VulnerabilityName: f.RuleName,
					Location:          fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.Line),
				}

				// Create işlemi artık her zaman INSERT olacak çünkü eskiler silindi
				if err := tx.Create(&finding).Error; err != nil {
					logger.Log.Errorf("Error saving Semgrep finding within transaction (ScanID: %s): %v. Details: %+v", scan.ID, err, finding)
					return fmt.Errorf("semgrep finding couldn't save: %w", err)
				}
				savedFindings = append(savedFindings, finding)
			}
		} else {
			logger.Log.Debugf("No findings returned from API for ScanID: %s. Previous findings (if any) were deleted.", scan.ID)
		}

		updateData := map[string]interface{}{
			"status":              models.ScanStatusCompleted,
			"vulnerability_count": len(savedFindings),
		}
		logger.Log.Debugf("Updating Scan %s final status to %s and count to %d within transaction.", scan.ID, models.ScanStatusCompleted, len(savedFindings))
		if err := tx.Model(&models.Scan{}).Where("id = ?", scan.ID).Updates(updateData).Error; err != nil {
			logger.Log.Errorf("Error updating scan status/count for ScanID %s within transaction: %v", scan.ID, err)
			return fmt.Errorf("failed to finalize scan record %s: %w", scan.ID, err)
		}

		return nil
	})
	if err != nil {
		logger.Log.Errorf("Failed transaction while processing findings for ScanID %s: %v", scan.ID, err)
		database.DB.Model(&scan).Where("status != ?", models.ScanStatusFailed).Update("status", models.ScanStatusFailed)
		return nil, err
	}

	logger.Log.Infof("Successfully processed Semgrep findings for ScanID: %s, TargetURL: %s. Found/Saved %d findings.", scan.ID, targetURLForScan, len(savedFindings))
	return savedFindings, nil
}

// Lists semgrep secrets findings
func (a *AssetService) SemgrepListSecrets(deploymentID string, userID uuid.UUID) ([]models.Finding, error) {
	logger.Log.Debugf("SemgrepListSecrets called for deployment ID: %s, user ID: %s", deploymentID, userID)  
	endpoint := fmt.Sprintf("/api/v1/deployments/%s/secrets", deploymentID)
	resp, err := utils.SendGETRequestSemgrep(endpoint, userID)
	if err != nil {
		logger.Log.Errorln("Error fetching Semgrep secrets:", err)
		return nil, fmt.Errorf("secrets couldn't fetch: %v", err)
	}
	defer resp.Body.Close()

	var response struct {
		Findings []struct {
			ID          string `json:"id"`
			Type        string `json:"type"`
			FindingPath string `json:"findingPath"`
			Repository  struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"repository"`
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
		} `json:"findings"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		logger.Log.Errorln("Error decoding Semgrep secrets response:", err)
		return nil, fmt.Errorf("secrets response couldn't handle: %v", err)
	}

	var findings []models.Finding
	for _, f := range response.Findings {
		finding := models.Finding{
			URL:               f.Repository.URL,
			Risk:              f.Severity,
			VulnerabilityName: fmt.Sprintf("Secret: %s", f.Type),
			Location:          f.FindingPath,
		}
		logger.Log.Debugf("Found Semgrep secret: %+v", finding)
		findings = append(findings, finding)
	}
	logger.Log.Infof("Retrieved %d Semgrep secrets for deployment ID: %s", len(findings), deploymentID)
	return findings, nil
}

// https://semgrep.dev/api/agent/deployments/{deployment_id}/repos/search
func (a *AssetService) SemgrepListRepositories(deploymentID string, userID uuid.UUID) ([]models.SemgrepRepoInfo, error) {
	logger.Log.Debugf("SemgrepListRepositories called for deployment ID: %s, user ID: %s", deploymentID, userID)
	semgrepSetting, err := utils.SemgrepGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Semgrep setting couldn't fetch:", err)
		return nil, err
	}

	url := fmt.Sprintf("https://semgrep.dev/api/agent/deployments/%s/repos/search", deploymentID)
	body := []byte(`{}`)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		logger.Log.Errorln("Request creation error:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+semgrepSetting.APIKey)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return nil, err
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		logger.Log.Errorf("Could not read response body from repositories fetch: %v", readErr)
		return nil, fmt.Errorf("failed to read repositories response body: %w", readErr)
	}
	defer resp.Body.Close()

	var responseData models.SemgrepRepository
	if err := json.Unmarshal(bodyBytes, &responseData); err != nil {
		logger.Log.Errorf("Error decoding Semgrep repositories response: %v. Response Body: %s", err, string(bodyBytes))
		return nil, fmt.Errorf("repositories response couldn't handle: %v", err)
	}

	logger.Log.Infof("Successfully decoded %d Semgrep repositories for deployment ID: %s", len(responseData.Repos), deploymentID)

	return responseData.Repos, nil
}