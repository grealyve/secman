package services

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/grealyve/lutenix/database"
	"github.com/grealyve/lutenix/logger"
	"github.com/grealyve/lutenix/models"
	"gorm.io/gorm"
)

type UserService struct{}

func (us *UserService) GetUserByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	if err := database.DB.Preload("Company").First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("Error during db query")
		return nil, err
	}
	return &user, nil
}

func (us *UserService) EmailExists(email string) (bool, error) {
	var count int64
	err := database.DB.Model(&models.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		logger.Log.Errorf("Error during db query")
	}

	return count > 0, err
}

func (us *UserService) CompanyExists(companyID uuid.UUID) (bool, error) {
	var count int64
	err := database.DB.Model(&models.Company{}).Where("id = ?", companyID).Count(&count).Error
	if err != nil {
		logger.Log.Errorf("Error during db query")
	}
	return count > 0, err
}

func (us *UserService) RegisterUser(user models.User) error {
	return database.DB.Create(&user).Error
}

func (us *UserService) GetOrCreateCompany(companyName string) (uuid.UUID, error) {
	var company models.Company

	err := database.DB.Where("name = ?", companyName).First(&company).Error
	if err == nil {
		logger.Log.Errorln("Company not found in db:", err)
		return company.ID, nil
	}

	if err == gorm.ErrRecordNotFound {
		newCompany := models.Company{
			Name: companyName,
		}

		if err := database.DB.Create(&newCompany).Error; err != nil {
			logger.Log.Errorf("Company couldn't create")
			return uuid.Nil, fmt.Errorf("company couldn't create: %v", err)
		}

		return newCompany.ID, nil
	}

	return uuid.Nil, err
}

func (us *UserService) UpdateUser(userID uuid.UUID, name, surname, email string) error {
	updates := map[string]any{}

	if name != "" {
		updates["name"] = name
	}
	if surname != "" {
		updates["surname"] = surname
	}
	if email != "" {
		updates["email"] = email
	}

	return database.DB.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error
}

func (us *UserService) UpdateScannerSetting(setting models.ScannerSetting) error {
	var existingSetting models.ScannerSetting
	result := database.DB.Where("company_id = ? AND scanner = ?", setting.CompanyID, setting.Scanner).First(&existingSetting)

	if result.Error == nil {
		updates := make(map[string]any)

		// Only include APIKey in the update if it's not empty
		if setting.APIKey != "" {
			updates["api_key"] = setting.APIKey
		}

		if setting.ScannerURL != "" {
			updates["scanner_url"] = setting.ScannerURL
		}

		if setting.ScannerPort != 0 {
			updates["scanner_port"] = setting.ScannerPort
		}

		if len(updates) == 0 {
			return nil
		}

		return database.DB.Model(&existingSetting).Updates(updates).Error

	} else if result.Error == gorm.ErrRecordNotFound {
		return database.DB.Create(&setting).Error
	}

	return result.Error
}

func (us *UserService) GetScannerSetting(userID uuid.UUID) (*models.ScannerSetting, error) {
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		return nil, err
	}

	var scannerSetting models.ScannerSetting
	if err := database.DB.Where("company_id = ?", user.CompanyID).First(&scannerSetting).Error; err != nil {
		return nil, err
	}

	return &scannerSetting, nil
}

func (us *UserService) CompanyExistsByName(companyName string) (bool, error) {
	var count int64
	err := database.DB.Model(&models.Company{}).Where("name = ?", companyName).Count(&count).Error
	if err != nil {
		logger.Log.Errorf("Error during company name check: %v", err)
	}
	return count > 0, err
}

func (us *UserService) CompanyExistsByID(companyID uuid.UUID) (bool, error) {
	var count int64
	err := database.DB.Model(&models.Company{}).Where("id = ?", companyID).Count(&count).Error
	if err != nil {
		logger.Log.Errorf("Error during company ID check: %v", err)
	}
	return count > 0, err
}

func (us *UserService) CreateCompany(companyName string) (uuid.UUID, error) {
	company := models.Company{
		Name: companyName,
	}

	if err := database.DB.Create(&company).Error; err != nil {
		logger.Log.Errorf("Error during company creation: %v", err)
		return uuid.Nil, err
	}

	return company.ID, nil
}

func (us *UserService) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		logger.Log.Errorf("Error retrieving user by email: %v", err)
		return nil, err
	}
	return &user, nil
}

func (us *UserService) UpdateUserCompany(userID uuid.UUID, companyID uuid.UUID) error {
	result := database.DB.Model(&models.User{}).Where("id = ?", userID).Update("company_id", companyID)
	if result.Error != nil {
		logger.Log.Errorf("Error updating user company: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		logger.Log.Warnf("No user was updated with ID: %s", userID)
	}

	return nil
}

func (us *UserService) GetCompanyIDByName(companyName string) (uuid.UUID, error) {
	var company models.Company
	if err := database.DB.Where("name = ?", companyName).First(&company).Error; err != nil {
		logger.Log.Errorf("Error retrieving company by name: %v", err)
		return uuid.Nil, err
	}
	return company.ID, nil
}

func (us *UserService) MakeAdmin(email string) error {
	result := database.DB.Model(&models.User{}).Where("email = ?", email).Update("role", "admin")
	if result.Error != nil {
		logger.Log.Errorf("Error making user admin: %v", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		logger.Log.Warnf("No user was updated with email: %s", email)
	}
	return nil
}

func (us *UserService) MakeUser(email string) error {
	result := database.DB.Model(&models.User{}).Where("email = ?", email).Update("role", "user")
	if result.Error != nil {
		logger.Log.Errorf("Error making user user: %v", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		logger.Log.Warnf("No user was updated with email: %s", email)
	}
	return nil
}

func (us *UserService) DeleteUser(email string) error {
	result := database.DB.Model(&models.User{}).Where("email = ?", email).Delete(&models.User{})
	if result.Error != nil {
		logger.Log.Errorf("Error deleting user: %v", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		logger.Log.Warnf("No user was deleted with email: %s", email)
	}
	return nil
}

func (us *UserService) GetUsers() ([]models.User, error) {
	var users []models.User
	err := database.DB.Find(&users).Error
	if err != nil {
		logger.Log.Errorf("Error retrieving users: %v", err)
		return nil, err
	}
	return users, nil
}

// GetUserProfileByID retrieves a user profile by user ID
func (us *UserService) GetUserProfileByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	if err := database.DB.Preload("Company").First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("Error retrieving user profile by ID %s: %v", userID, err)
		return nil, err
	}
	return &user, nil
}

// GetScannerSettingByUserID retrieves scanner settings for a specific user
func (us *UserService) GetScannerSettingByUserID(userID uuid.UUID) (*models.ScannerSetting, error) {
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		logger.Log.Errorf("Error retrieving user for scanner settings by ID %s: %v", userID, err)
		return nil, err
	}

	var scannerSetting models.ScannerSetting
	if err := database.DB.Where("company_id = ?", user.CompanyID).First(&scannerSetting).Error; err != nil {
		logger.Log.Errorf("Error retrieving scanner setting for user %s: %v", userID, err)
		return nil, err
	}

	return &scannerSetting, nil
}

// GetFindingsByCompanyID retrieves all findings for a specific company
func (us *UserService) GetFindingsByCompanyID(companyID uuid.UUID) ([]models.Finding, error) {
	var findings []models.Finding

	err := database.DB.Joins("JOIN scans ON findings.scan_id = scans.id").
		Where("scans.company_id = ?", companyID).
		Find(&findings).Error

	if err != nil {
		logger.Log.Errorf("Error retrieving findings for company %s: %v", companyID, err)
		return nil, err
	}

	return findings, nil
}

func (us *UserService) GetUserByEmailV(email string) (*models.User, error) {
    var user models.User
    
    query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
    err := database.DB.Raw(query).Scan(&user).Error
    
    return &user, err
}

func (us *UserService) SearchUsersV(searchTerm string) ([]models.User, error) {
    var users []models.User
    
    query := "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'"
    err := database.DB.Raw(query).Scan(&users).Error
    
    return users, err
}

func (us *UserService) GetUsersWithFilterV(role string, companyID string) ([]models.User, error) {
    var users []models.User
    
    whereClause := "role = '" + role + "'"
    if companyID != "" {
        whereClause += " AND company_id = '" + companyID + "'"
    }
    
    err := database.DB.Raw("SELECT * FROM users WHERE " + whereClause).Scan(&users).Error
    return users, err
}