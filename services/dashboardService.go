package services

import (
	"github.com/google/uuid"
	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/models"
)

type DashboardService struct {}

// Initialize a new dashboard service
func NewDashboardService() *DashboardService {
	return &DashboardService{}
}

// GetTotalScans returns the total number of scans for a company
func (ds *DashboardService) GetTotalScans(companyID uuid.UUID) (int64, error) {
	var count int64
	err := database.DB.Model(&models.Scan{}).Where("company_id = ?", companyID).Count(&count).Error
	return count, err
}

// GetScansByType returns the count of scans by scanner type
func (ds *DashboardService) GetScansByType(companyID uuid.UUID) ([]map[string]interface{}, error) {
	var results []struct {
		Scanner string `json:"scanner"`
		Count   int    `json:"count"`
	}
	
	err := database.DB.Model(&models.Scan{}).
		Select("scanner, count(*) as count").
		Where("company_id = ?", companyID).
		Group("scanner").
		Find(&results).Error
	
	if err != nil {
		return nil, err
	}
	
	// Convert to the generic map format for easier JSON handling
	output := make([]map[string]interface{}, len(results))
	for i, result := range results {
		output[i] = map[string]interface{}{
			"scanner": result.Scanner,
			"count":   result.Count,
		}
	}
	
	return output, nil
}

// GetScansByStatus returns the count of scans by status
func (ds *DashboardService) GetScansByStatus(companyID uuid.UUID) ([]map[string]interface{}, error) {
	var results []struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	
	err := database.DB.Model(&models.Scan{}).
		Select("status, count(*) as count").
		Where("company_id = ?", companyID).
		Group("status").
		Find(&results).Error
	
	if err != nil {
		return nil, err
	}
	
	// Convert to the generic map format for easier JSON handling
	output := make([]map[string]interface{}, len(results))
	for i, result := range results {
		output[i] = map[string]interface{}{
			"status": result.Status,
			"count":  result.Count,
		}
	}
	
	return output, nil
}

// GetTotalVulnerabilities returns the total number of vulnerabilities for a company
func (ds *DashboardService) GetTotalVulnerabilities(companyID uuid.UUID) (int64, error) {
	var count int64
	err := database.DB.Model(&models.Scan{}).
		Where("company_id = ?", companyID).
		Select("SUM(vulnerability_count)").
		Scan(&count).Error
	return count, err
}

// GetRecentScans returns the most recent scans for a company
func (ds *DashboardService) GetRecentScans(companyID uuid.UUID, limit int) ([]models.Scan, error) {
	var scans []models.Scan
	err := database.DB.Model(&models.Scan{}).
		Where("company_id = ?", companyID).
		Order("created_at DESC").
		Limit(limit).
		Find(&scans).Error
	return scans, err
}

// GetFindingsBySeverity returns the count of findings by severity
func (ds *DashboardService) GetFindingsBySeverity(companyID uuid.UUID) ([]map[string]interface{}, error) {
	var results []struct {
		Risk   string `json:"Risk"`
		Count  int    `json:"count"`
	}
	
	err := database.DB.Model(&models.Finding{}).
		Select("risk, count(*) as count").
		Joins("JOIN scans ON findings.scan_id = scans.id").
		Where("scans.company_id = ?", companyID).
		Group("risk").
		Find(&results).Error
	
	if err != nil {
		return nil, err
	}
	
	// Convert to the generic map format for easier JSON handling
	output := make([]map[string]interface{}, len(results))
	for i, result := range results {
		output[i] = map[string]interface{}{
			"risk":   result.Risk,
			"count":  result.Count,
		}
	}
	
	return output, nil
}
