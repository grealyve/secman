package controller

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grealyve/lutenix/logger"
	"github.com/grealyve/lutenix/models"
	"github.com/grealyve/lutenix/services"
	"golang.org/x/crypto/bcrypt"
)

type UserController struct {
	UserService *services.UserService
}

func NewUserController() *UserController {
	return &UserController{
		UserService: &services.UserService{},
	}
}

func (uc *UserController) RegisterUser(c *gin.Context) {
	var body struct {
		Name     string `json:"name" binding:"required"`
		Surname  string `json:"surname" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	logger.Log.Debugln("RegisterUser endpoint called")

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Log.Errorln("Invalid registration request", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	logger.Log.Debugf("RegisterUser request body: %+v", body)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Errorln("Password hashing failed", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed: " + err.Error()})
		return
	}

	exists, err := uc.UserService.EmailExists(body.Email)
	if err != nil {
		logger.Log.Errorln("Email check failed in database query", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Email check failed: " + err.Error()})
		return
	}
	if exists {
		logger.Log.Infoln("Registration attempted with existing email:", body.Email)
		c.JSON(http.StatusConflict, gin.H{"error": "This email already in use"})
		return
	}

	// Get or create default company for users
	defaultCompanyName := "Default Company"
	companyID, err := uc.UserService.GetOrCreateCompany(defaultCompanyName)
	if err != nil {
		logger.Log.Errorln("Default company creation or retrieval failed", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Default company creation failed: " + err.Error()})
		return
	}
	logger.Log.Debugf("Using default company ID: %s", companyID)

	user := models.User{
		Name:      body.Name,
		Surname:   body.Surname,
		Email:     body.Email,
		Password:  string(hashedPassword),
		Role:      "user",
		CompanyID: companyID,
	}

	err = uc.UserService.RegisterUser(user)
	if err != nil {
		logger.Log.Errorln("User couldn't be saved", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User couldn't be saved: " + err.Error()})
		return
	}

	logger.Log.Infoln("User registered successfully:", user.Email)

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user": gin.H{
			"id":         user.ID,
			"name":       user.Name,
			"surname":    user.Surname,
			"email":      user.Email,
			"role":       user.Role,
			"company_id": user.CompanyID,
		},
	})
}

func (uc *UserController) CreateCompany(c *gin.Context) {
	logger.Log.Debugln("CreateCompany endpoint called")

	// Safely get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		logger.Log.Errorln("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	userIDUUID, ok := userID.(uuid.UUID)
	if !ok {
		logger.Log.Errorln("Invalid user ID format in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		return
	}

	logger.Log.Debugf("User ID: %s attempting to create company", userIDUUID)

	var body struct {
		CompanyName string `json:"company_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Log.Errorln("Invalid company creation request", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	logger.Log.Debugf("Company creation request body: %+v", body)

	exists, err := uc.UserService.CompanyExistsByName(body.CompanyName)
	if err != nil {
		logger.Log.Errorln("Company existence check failed", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Company check failed: " + err.Error()})
		return
	}

	if exists {
		logger.Log.Infoln("Company creation attempted with existing name:", body.CompanyName)
		c.JSON(http.StatusConflict, gin.H{"error": "Company with this name already exists"})
		return
	}

	companyID, err := uc.UserService.CreateCompany(body.CompanyName)
	if err != nil {
		logger.Log.Errorln("Company creation failed", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Company creation failed: " + err.Error()})
		return
	}

	logger.Log.Infoln("Company created successfully:", body.CompanyName, "with ID:", companyID)

	c.JSON(http.StatusCreated, gin.H{
		"message": "Company created successfully",
		"company": gin.H{
			"id":   companyID,
			"name": body.CompanyName,
		},
	})
}

func (uc *UserController) AddUserToCompany(c *gin.Context) {
	logger.Log.Debugln("AddUserToCompany endpoint called")

	// Safely get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		logger.Log.Errorln("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	adminID, ok := userID.(uuid.UUID)
	if !ok {
		logger.Log.Errorln("Invalid user ID format in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID format"})
		return
	}

	logger.Log.Debugf("User ID: %s attempting to add user to company", adminID)

	var body struct {
		Email       string `json:"email" binding:"required,email"`
		CompanyName string `json:"company_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Log.Errorln("Invalid add user to company request", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	logger.Log.Debugf("Add user to company request body: %+v", body)

	user, err := uc.UserService.GetUserByEmail(body.Email)
	if err != nil {
		logger.Log.Errorln("User not found:", body.Email, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found with the provided email"})
		return
	}

	// Check if company exists by name
	exists, err = uc.UserService.CompanyExistsByName(body.CompanyName)
	if err != nil {
		logger.Log.Errorln("Company check failed", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Company check failed: " + err.Error()})
		return
	}

	if !exists {
		logger.Log.Errorln("Company not found:", body.CompanyName)
		c.JSON(http.StatusNotFound, gin.H{"error": "Company not found with the provided name"})
		return
	}

	// Get company ID by name
	companyID, err := uc.UserService.GetCompanyIDByName(body.CompanyName)
	if err != nil {
		logger.Log.Errorln("Failed to get company ID", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get company ID: " + err.Error()})
		return
	}

	if err := uc.UserService.UpdateUserCompany(user.ID, companyID); err != nil {
		logger.Log.Errorln("Failed to add user to company", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to company: " + err.Error()})
		return
	}

	logger.Log.Infoln("User", user.Email, "successfully added to company", body.CompanyName)

	c.JSON(http.StatusOK, gin.H{
		"message": "User successfully added to company",
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
		},
		"company_name": body.CompanyName,
	})
}

func (uc *UserController) GetMyProfile(c *gin.Context) {
	logger.Log.Debugln("GetMyProfile endpoint called")

	userID, exists := c.Get("userID")
	if !exists {
		logger.Log.Errorln("User ID couldn't find in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID couldn't find in context"})
		return
	}

	userIDUUID, ok := userID.(uuid.UUID)
	if !ok {
		logger.Log.Errorln("UUID conversion failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "UUID conversion failed"})
		return
	}
	logger.Log.Debugf("Current user ID: %s", userIDUUID)

	user, err := uc.UserService.GetUserByID(userIDUUID)
	if err != nil {
		logger.Log.Infoln("User not found for current user:", userIDUUID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User couldn't find"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (uc *UserController) UpdateProfile(c *gin.Context) {
	logger.Log.Debugln("UpdateProfile endpoint called")
	userID := c.MustGet("userID").(uuid.UUID)
	logger.Log.Debugf("UpdateProfile for user ID: %s", userID)

	var body struct {
		Name    string `json:"name"`
		Surname string `json:"surname"`
		Email   string `json:"email"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Log.Errorln("Invalid request body for UpdateProfile", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}
	logger.Log.Debugf("UpdateProfile request body: %+v", body)

	if body.Email != "" {
		exists, err := uc.UserService.EmailExists(body.Email)
		if err != nil {
			logger.Log.Errorln("Email existence check failed during profile update", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Email check couldn't complete"})
			return
		}
		if exists {
			logger.Log.Infoln("Profile update attempted with existing email:", body.Email)
			c.JSON(http.StatusConflict, gin.H{"error": "This email address is already in use"})
			return
		}
	}

	if err := uc.UserService.UpdateUser(userID, body.Name, body.Surname, body.Email); err != nil {
		logger.Log.Errorln("User update failed during query", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Profile couldn't update"})
		return
	}

	logger.Log.Infoln("Profile updated successfully for user:", userID)
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

func (uc *UserController) UpdateScannerSetting(c *gin.Context) {
	logger.Log.Debugln("UpdateScannerSetting endpoint called // Debug: Entry point")
	userID := c.MustGet("userID").(uuid.UUID)
	logger.Log.Debugf("Updating scanner settings for user ID: %s", userID)

	var body struct {
		Scanner     string `json:"scanner" binding:"required,oneof=acunetix semgrep zap"`
		APIKey      string `json:"api_key" binding:"required"`
		ScannerURL  string `json:"scanner_url"`
		ScannerPort int    `json:"scanner_port"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Log.Errorln("Invalid UpdateScannerSetting request", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	logger.Log.Debugf("UpdateScannerSetting request body: %+v", body)

	user, err := uc.UserService.GetUserByID(userID)
	if err != nil {
		logger.Log.Errorln("User data couldn't be retrieved for scanner setting update", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User data couldn't find"})
		return
	}

	scannerSetting := models.ScannerSetting{
		CreatedBy:   userID,
		CompanyID:   user.CompanyID,
		Scanner:     body.Scanner,
		APIKey:      body.APIKey,
		ScannerURL:  body.ScannerURL,
		ScannerPort: body.ScannerPort,
	}

	if err := uc.UserService.UpdateScannerSetting(scannerSetting); err != nil {
		logger.Log.Errorln("Scanner settings update failed", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Scanner couldn't update"})
		return
	}

	logger.Log.Infoln("Scanner settings updated successfully for user:", userID) // Info: Success
	c.JSON(http.StatusOK, gin.H{"message": "Scanner settings updated successfully"})
}

func (uc *UserController) GetScannerSetting(c *gin.Context) {
	logger.Log.Debugln("GetScannerSetting endpoint called // Debug: Entry Point")
	userID := c.MustGet("userID").(uuid.UUID)
	logger.Log.Debugf("Retrieving scanner settings for user ID: %s", userID)

	scannerSetting, err := uc.UserService.GetScannerSetting(userID)
	if err != nil {
		logger.Log.Errorln("Scanner data couldn't be retrieved", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Scanner data couldn't find"})
		return
	}

	c.JSON(http.StatusOK, scannerSetting)
}

func (uc *UserController) MakeAdmin(c *gin.Context) {
	var request struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := uc.UserService.MakeAdmin(request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User role updated to admin successfully"})
}

func (uc *UserController) MakeUser(c *gin.Context) {
	var request struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := uc.UserService.MakeUser(request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User role updated to user successfully"})
}

func (uc *UserController) DeleteUser(c *gin.Context) {
	var request struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := uc.UserService.DeleteUser(request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func (uc *UserController) GetUsers(c *gin.Context) {
	users, err := uc.UserService.GetUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (uc *UserController) GetUserProfileByID(c *gin.Context) {
	logger.Log.Debugln("GetUserProfileByID endpoint called")
	userID := c.Param("user_id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		logger.Log.Errorln("Invalid user ID format:", userID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logger.Log.Debugf("Retrieving profile for user ID: %s", userUUID)
	user, err := uc.UserService.GetUserProfileByID(userUUID)
	if err != nil {
		logger.Log.Errorln("User profile not found:", userUUID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	logger.Log.Infoln("User profile retrieved successfully for:", userUUID)
	c.JSON(http.StatusOK, user)
}

func (uc *UserController) GetScannerSettingByUserID(c *gin.Context) {
	logger.Log.Debugln("GetScannerSettingByUserID endpoint called")
	targetUserID := c.Param("user_id")

	targetUUID, err := uuid.Parse(targetUserID)
	if err != nil {
		logger.Log.Errorln("Invalid user ID format:", targetUserID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logger.Log.Debugf("Retrieving scanner settings for user ID: %s", targetUUID)
	scannerSetting, err := uc.UserService.GetScannerSettingByUserID(targetUUID)
	if err != nil {
		logger.Log.Errorln("Scanner setting not found for user:", targetUUID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Scanner setting not found"})
		return
	}

	logger.Log.Infoln("Scanner settings retrieved successfully for user:", targetUUID)
	c.JSON(http.StatusOK, scannerSetting)
}

func (uc *UserController) GetFindingsByCompanyID(c *gin.Context) {
	logger.Log.Debugln("GetFindingsByCompanyID endpoint called")
	companyID := c.Param("company_id")

	companyUUID, err := uuid.Parse(companyID)
	if err != nil {
		logger.Log.Errorln("Invalid company ID format:", companyID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid company ID"})
		return
	}

	logger.Log.Debugf("Retrieving findings for company ID: %s", companyUUID)
	findings, err := uc.UserService.GetFindingsByCompanyID(companyUUID)
	if err != nil {
		logger.Log.Errorln("Failed to retrieve findings for company:", companyUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve findings"})
		return
	}

	logger.Log.Infoln("Findings retrieved successfully for company:", companyUUID)
	c.JSON(http.StatusOK, gin.H{"findings": findings})
}

// VULNERABLE ENDPOINTS FOR TESTING PURPOSES ONLY
// These endpoints contain SQL injection vulnerabilities and should not be used in production

func (uc *UserController) GetUserByEmailV(c *gin.Context) {
	logger.Log.Debugln("GetUserByEmailV endpoint called (VULNERABLE)")

	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email parameter is required"})
		return
	}

	logger.Log.Debugf("Retrieving user by email (VULNERABLE): %s", email)
	user, err := uc.UserService.GetUserByEmailV(email)
	if err != nil {
		logger.Log.Errorln("Failed to retrieve user by email (VULNERABLE):", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (uc *UserController) SearchUsersV(c *gin.Context) {
	logger.Log.Debugln("SearchUsersV endpoint called (VULNERABLE)")

	searchTerm := c.Query("search")
	if searchTerm == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search parameter is required"})
		return
	}

	logger.Log.Debugf("Searching users with term (VULNERABLE): %s", searchTerm)
	users, err := uc.UserService.SearchUsersV(searchTerm)
	if err != nil {
		logger.Log.Errorln("Failed to search users (VULNERABLE):", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (uc *UserController) GetUsersWithFilterV(c *gin.Context) {
	logger.Log.Debugln("GetUsersWithFilterV endpoint called (VULNERABLE)")

	role := c.Query("role")
	companyID := c.Query("company_id")

	if role == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role parameter is required"})
		return
	}

	logger.Log.Debugf("Getting users with filter (VULNERABLE) - role: %s, company_id: %s", role, companyID)
	users, err := uc.UserService.GetUsersWithFilterV(role, companyID)
	if err != nil {
		logger.Log.Errorln("Failed to get users with filter (VULNERABLE):", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// IDOR VULNERABLE ENDPOINTS FOR TESTING PURPOSES ONLY
// These endpoints contain IDOR vulnerabilities and should not be used in production

// uuidToSequentialID converts UUID to sequential integer ID for IDOR testing
func (uc *UserController) uuidToSequentialID(targetUUID uuid.UUID, entityType string) (int, error) {
	var uuids []uuid.UUID

	switch entityType {
	case "user":
		users, err := uc.UserService.GetUsers()
		if err != nil {
			return 0, err
		}
		for _, user := range users {
			uuids = append(uuids, user.ID)
		}
	case "company":
		companies, err := uc.UserService.GetCompanies()
		if err != nil {
			return 0, err
		}
		for _, company := range companies {
			uuids = append(uuids, company.ID)
		}
	}

	// Sort UUIDs for consistent mapping
	sort.Slice(uuids, func(i, j int) bool {
		return uuids[i].String() < uuids[j].String()
	})

	// Find the target UUID and return its sequential position
	for i, uuid := range uuids {
		if uuid == targetUUID {
			return i + 1, nil // Start from 1 instead of 0
		}
	}

	return 0, nil
}

// sequentialIDToUUID converts sequential integer ID back to UUID for IDOR testing
func (uc *UserController) sequentialIDToUUID(sequentialID int, entityType string) (uuid.UUID, error) {
	var uuids []uuid.UUID

	switch entityType {
	case "user":
		users, err := uc.UserService.GetUsers()
		if err != nil {
			return uuid.Nil, err
		}
		for _, user := range users {
			uuids = append(uuids, user.ID)
		}
	case "company":
		companies, err := uc.UserService.GetCompanies()
		if err != nil {
			return uuid.Nil, err
		}
		for _, company := range companies {
			uuids = append(uuids, company.ID)
		}
	}

	// Sort UUIDs for consistent mapping
	sort.Slice(uuids, func(i, j int) bool {
		return uuids[i].String() < uuids[j].String()
	})

	// Return the UUID at the sequential position
	if sequentialID > 0 && sequentialID <= len(uuids) {
		return uuids[sequentialID-1], nil // Convert from 1-based to 0-based indexing
	}

	return uuid.Nil, nil
}

// GetUserProfileByIDV - IDOR vulnerable version using sequential IDs
func (uc *UserController) GetUserProfileByIDV(c *gin.Context) {
	logger.Log.Debugln("GetUserProfileByIDV endpoint called (VULNERABLE - IDOR)")
	userIDStr := c.Param("user_id")

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Log.Errorln("Invalid user ID format:", userIDStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logger.Log.Debugf("Retrieving profile for user ID (VULNERABLE - IDOR): %d", userID)

	// Convert sequential ID to UUID - THIS IS THE VULNERABILITY
	userUUID, err := uc.sequentialIDToUUID(userID, "user")
	if err != nil {
		logger.Log.Errorln("Failed to convert sequential ID to UUID:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	if userUUID == uuid.Nil {
		logger.Log.Errorln("User not found for ID:", userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user, err := uc.UserService.GetUserProfileByID(userUUID)
	if err != nil {
		logger.Log.Errorln("User profile not found:", userUUID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	logger.Log.Warnf("IDOR VULNERABILITY: User profile retrieved for sequential ID %d (UUID: %s)", userID, userUUID)
	c.JSON(http.StatusOK, user)
}

// GetScannerSettingByUserIDV - IDOR vulnerable version using sequential IDs
func (uc *UserController) GetScannerSettingByUserIDV(c *gin.Context) {
	logger.Log.Debugln("GetScannerSettingByUserIDV endpoint called (VULNERABLE - IDOR)")
	userIDStr := c.Param("user_id")

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		logger.Log.Errorln("Invalid user ID format:", userIDStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	logger.Log.Debugf("Retrieving scanner settings for user ID (VULNERABLE - IDOR): %d", userID)

	// Convert sequential ID to UUID - THIS IS THE VULNERABILITY
	userUUID, err := uc.sequentialIDToUUID(userID, "user")
	if err != nil {
		logger.Log.Errorln("Failed to convert sequential ID to UUID:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve scanner settings"})
		return
	}

	if userUUID == uuid.Nil {
		logger.Log.Errorln("User not found for ID:", userID)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	scannerSetting, err := uc.UserService.GetScannerSettingByUserID(userUUID)
	if err != nil {
		logger.Log.Errorln("Scanner setting not found for user:", userUUID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Scanner setting not found"})
		return
	}

	logger.Log.Warnf("IDOR VULNERABILITY: Scanner settings retrieved for sequential ID %d (UUID: %s)", userID, userUUID)
	c.JSON(http.StatusOK, scannerSetting)
}

// GetFindingsByCompanyIDV - IDOR vulnerable version using sequential IDs
func (uc *UserController) GetFindingsByCompanyIDV(c *gin.Context) {
	logger.Log.Debugln("GetFindingsByCompanyIDV endpoint called (VULNERABLE - IDOR)")
	companyIDStr := c.Param("company_id")

	companyID, err := strconv.Atoi(companyIDStr)
	if err != nil {
		logger.Log.Errorln("Invalid company ID format:", companyIDStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid company ID"})
		return
	}

	logger.Log.Debugf("Retrieving findings for company ID (VULNERABLE - IDOR): %d", companyID)

	// Convert sequential ID to UUID - THIS IS THE VULNERABILITY
	companyUUID, err := uc.sequentialIDToUUID(companyID, "company")
	if err != nil {
		logger.Log.Errorln("Failed to convert sequential ID to UUID:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve findings"})
		return
	}

	if companyUUID == uuid.Nil {
		logger.Log.Errorln("Company not found for ID:", companyID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Company not found"})
		return
	}

	findings, err := uc.UserService.GetFindingsByCompanyID(companyUUID)
	if err != nil {
		logger.Log.Errorln("Failed to retrieve findings for company:", companyUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve findings"})
		return
	}

	logger.Log.Warnf("IDOR VULNERABILITY: Findings retrieved for sequential ID %d (UUID: %s)", companyID, companyUUID)
	c.JSON(http.StatusOK, gin.H{"findings": findings})
}
