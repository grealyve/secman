package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/grealyve/secman/config"
	"github.com/grealyve/secman/database"
	"github.com/grealyve/secman/logger"
	"github.com/grealyve/secman/models"
)

var (
	ConfigInstance *config.Config
	tr             = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{Transport: tr}
)

func SendCustomRequestAcunetix(requestMethod string, endpoint string, body []byte, userID uuid.UUID) (*http.Response, error) {
	acunetixSetting, err := AcunetixGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Acunetix setting couldn't fetch:", err)
		return nil, err
	}

	req, err := http.NewRequest(requestMethod, acunetixSetting.ScannerURL+":"+strconv.Itoa(acunetixSetting.ScannerPort)+endpoint, bytes.NewBuffer(body))
	if err != nil {
		logger.Log.Errorln("Request creation error:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth", acunetixSetting.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return nil, err
	}

	return resp, nil
}

func SendGETRequestAcunetix(endpoint string, userID uuid.UUID) (*http.Response, error) {
	acunetixSetting, err := AcunetixGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Acunetix setting couldn't fetch:", err)
		return nil, err
	}

	req, err := http.NewRequest("GET", acunetixSetting.ScannerURL+":"+strconv.Itoa(acunetixSetting.ScannerPort)+endpoint, nil)
	if err != nil {
		logger.Log.Errorln("Request creation error:", err)
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth", acunetixSetting.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return nil, err
	}

	return resp, nil
}

func SendGETRequestZap(endpoint, apiKey string, scannerURL string, scannerPort int) (*http.Response, error) {
	url := fmt.Sprintf("%s:%d%s", scannerURL, scannerPort, endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Log.Errorln("Request creation error:", err)
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return nil, err
	}

	return resp, nil
}

func SendGETRequestSemgrep(endpoint string, userID uuid.UUID) (*http.Response, error) {
	semgrepSetting, err := SemgrepGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Semgrep setting couldn't fetch:", err)
		return nil, err
	}

	url := fmt.Sprintf(semgrepSetting.ScannerURL+":"+strconv.Itoa(semgrepSetting.ScannerPort)+"%v", endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Log.Errorln("Request creation error:", err)
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+semgrepSetting.APIKey)

	return client.Do(req)
}

func SendCustomRequestSemgrep(requestMethod string, endpoint string, body []byte, userID uuid.UUID) (*http.Response, error) {
	semgrepSetting, err := SemgrepGetUserSettings(userID)
	if err != nil {
		logger.Log.Errorln("Semgrep setting couldn't fetch:", err)
		return nil, err
	}

	url := fmt.Sprintf(semgrepSetting.ScannerURL+"%v", endpoint)

	req, err := http.NewRequest(requestMethod, url, bytes.NewBuffer(body))
	if err != nil {
		logger.Log.Errorln("Request creation error:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+semgrepSetting.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		logger.Log.Errorln("Request error:", err)
		return nil, err
	}

	return resp, nil
}

func SemgrepGetUserSettings(userID uuid.UUID) (*models.ScannerSetting, error) {
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		return nil, fmt.Errorf("user setting couldn't fetch: %v", err)
	}

	var scannerSetting models.ScannerSetting
	if err := database.DB.Where("company_id = ? AND scanner = ?", user.CompanyID, "semgrep").First(&scannerSetting).Error; err != nil {
		return nil, fmt.Errorf("semgrep scanner settings couldn't find: %v", err)
	}

	return &scannerSetting, nil
}

func AcunetixGetUserSettings(userID uuid.UUID) (*models.ScannerSetting, error) {
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		return nil, fmt.Errorf("user setting couldn't find: %v", err)
	}

	var scannerSetting models.ScannerSetting
	if err := database.DB.Where("company_id = ? AND scanner = ?", user.CompanyID, "acunetix").First(&scannerSetting).Error; err != nil {
		return nil, fmt.Errorf("semgrep scanner settings couldn't find: %v", err)
	}

	return &scannerSetting, nil
}
