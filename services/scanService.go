package services

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/models"
)

type ScanService struct {
}

func (s *ScanService) GetActiveScanByUserID(userID uuid.UUID) (*models.Scan, error) {
	logTag := "GetActiveScanByUserID"
	logger.Log.Debugf("[%s] Called for UserID: %s", logTag, userID)

	var scan models.Scan
	result := database.DB.Where("created_by = ? AND status IN (?, ?)",
		userID,
		models.ScanStatusProcessing,
		models.ScanStatusCompleted).
		Order("created_at DESC").
		First(&scan)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			logger.Log.Warnf("[%s] No active scan found for UserID %s", logTag, userID)
			return nil, fmt.Errorf("no active scan found for user")
		}
		logger.Log.Errorf("[%s] Error querying active scan for UserID %s: %v", logTag, userID, result.Error)
		return nil, fmt.Errorf("failed to retrieve active scan: %w", result.Error)
	}

	logger.Log.Debugf("[%s] Active scan found for UserID %s: ScanID=%s", logTag, userID, scan.ID)
	return &scan, nil
}

type ScannerService struct{}
