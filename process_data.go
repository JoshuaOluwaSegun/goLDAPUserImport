package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/go-objectsid"
	"github.com/google/uuid"
	"github.com/hornbill/ldap"
)

// -- Store LDAP Usres in Map
func processLDAPUsers() {
	logger(1, "Processing LDAP User Data", true)

	//-- User Working Data
	HornbillCache.UsersWorking = make(map[string]*userWorkingDataStruct)
	HornbillCache.Managers = make(map[string]string)
	HornbillCache.DN = make(map[string]string)
	HornbillCache.Images = make(map[string]imageStruct)
	//-- Loop LDAP Users
	for user := range ldapUsers {
		// Process Pre Import Actions
		userID := processImportActions(ldapUsers[user])

		// Process Params and return userId
		if userID != "" {
			processUserParams(ldapUsers[user], userID)
			var userDN = processComplexField(ldapUsers[user], ldapImportConf.User.UserDN, true)
			//-- Write to Cache
			writeUserToCache(userDN, userID)
		}
	}

	logger(1, "LDAP Users Processed: "+fmt.Sprintf("%d", len(ldapUsers))+"\n", true)
}

func generateUniqueGUID() string {

	userIdToCheck := ""
	userExists := true

	for ok := true; ok; ok = userExists {
		id := uuid.New()
		userIdToCheck = id.String()
		userExists = false
		for _, checkHornbillUserData := range HornbillCache.Users {
			if strings.EqualFold(checkHornbillUserData.HUserID, userIdToCheck) {
				userExists = true
				break
			}
		}
	}
	logger(1, "Generated GUID: "+userIdToCheck, false)
	return userIdToCheck
}

func processData() {
	logger(1, "Processing User Data", true)
	for user := range HornbillCache.UsersWorking {

		currentUser := HornbillCache.UsersWorking[user]

		userID := strings.ToLower(currentUser.Account.UserID)

		userExists := false
		var hornbillUserData userAccountStruct
		if checkHornbillUserData, ok := HornbillCache.Users[strings.ToLower(currentUser.Account.CheckID)]; ok {
			userExists = true
			hornbillUserData = checkHornbillUserData
		}

		//-- Check Map no need to loop
		if userExists {
			logger(1, "LDAP User ID: '"+userID+"'", false)
			if strings.ToLower(ldapImportConf.User.Operation) == "update" || strings.ToLower(ldapImportConf.User.Operation) == "both" {
				currentUser.Jobs.id = hornbillUserData.HUserID
				currentUser.Jobs.update = checkUserNeedsUpdate(currentUser, hornbillUserData)

				currentUser.Jobs.updateProfile = checkUserNeedsProfileUpdate(currentUser, hornbillUserData)

				currentUser.Jobs.updateType = checkUserNeedsTypeUpdate(currentUser, hornbillUserData)

				currentUser.Jobs.updateSite = checkUserNeedsSiteUpdate(currentUser, hornbillUserData)

				currentUser.Jobs.updateImage = checkUserNeedsImageUpdate(currentUser, hornbillUserData)

				currentUser.Jobs.updateHomeOrg = checkUserNeedsHomeOrgUpdate(currentUser, hornbillUserData)

				checkUserNeedsOrgUpdate(currentUser, hornbillUserData)

				checkUserNeedsOrgRemoving(currentUser, hornbillUserData)

				checkUserNeedsRoleUpdate(currentUser, hornbillUserData)

				currentUser.Jobs.updateStatus = checkUserNeedsStatusUpdate(currentUser, hornbillUserData)
			}
		} else {
			if strings.ToLower(ldapImportConf.User.Operation) == "create" || strings.ToLower(ldapImportConf.User.Operation) == "both" && userID != "" {

				//userID was lowercased
				if userID == "auto_generated_guid" {
					logger(1, "LDAP User ID: NOT Found - Generating GUID", false)
					GUID := generateUniqueGUID()
					HornbillCache.UsersWorking[user].Jobs.id = GUID
					HornbillCache.UsersWorking[user].Account.UserID = GUID
					userID = GUID
				} else {
					logger(1, "LDAP User ID: '"+userID+"' NOT Found", false)
					currentUser.Jobs.id = userID
				}

				if userID == "" {
					CounterInc(7)
					logger(4, "LDAP Record Has no User ID: '"+fmt.Sprintf("%+v", currentUser.LDAP)+"'\n", false)
					continue
				}

				//-- Check for Password
				setUserPasswordValueForCreate(currentUser)
				//-- Set Site ID Based on Config
				setUserSiteValueForCreate(currentUser, hornbillUserData)
				setUserRolesalueForCreate(currentUser, hornbillUserData)
				currentUser.Jobs.updateImage = checkUserNeedsImageCreate(currentUser, hornbillUserData)
				checkUserNeedsOrgCreate(currentUser, hornbillUserData)
				currentUser.Jobs.updateStatus = checkUserNeedsStatusCreate(currentUser, hornbillUserData)
				// reversal to be back to 3.7.1 currentUser.Jobs.updateProfile = checkUserNeedsProfileUpdate(currentUser, hornbillUserData)
				currentUser.Jobs.create = true
			}
		}

		loggerOutput := []string{
			"User: " + userID,
			"Hornbill User ID: " + currentUser.Jobs.id,
			"Checked ID: " + currentUser.Account.CheckID,
			"Operation: " + ldapImportConf.User.Operation,
			"User Exists: " + strconv.FormatBool(userExists),
			"Create: " + strconv.FormatBool(currentUser.Jobs.create),
			"Update: " + strconv.FormatBool(currentUser.Jobs.update),
			"Update Type: " + strconv.FormatBool(currentUser.Jobs.updateType),
			"Update Profile: " + strconv.FormatBool(currentUser.Jobs.updateProfile),
			"Update Site: " + strconv.FormatBool(currentUser.Jobs.updateSite),
			"Update Status: " + strconv.FormatBool(currentUser.Jobs.updateStatus),
			"Update Home Organisation: " + strconv.FormatBool(currentUser.Jobs.updateHomeOrg),
			"Roles Count: " + fmt.Sprintf("%d", len(currentUser.Roles)),
			"Update Image: " + strconv.FormatBool(currentUser.Jobs.updateImage),
			"Groups: " + fmt.Sprintf("%d", len(currentUser.Groups)),
			"Enable2FA: " + currentUser.Account.Enable2FA,
			"DisableDirectLogin: " + currentUser.Account.DisableDirectLogin,
			"DisableDirectLoginPasswordReset: " + currentUser.Account.DisableDirectLoginPasswordReset,
			"DisableDevicePairing: " + currentUser.Account.DisableDevicePairing}

		strings.Join(loggerOutput[:], "\n\t")
		logger(1, strings.Join(loggerOutput[:], "\n\t")+"\n", false)
	}
	logger(1, "User Data Processed: "+fmt.Sprintf("%d", len(HornbillCache.UsersWorking))+"", true)
}

func checkUserNeedsStatusCreate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {

	if ldapImportConf.User.Role.Action == "Both" || ldapImportConf.User.Role.Action == "Create" {
		//-- By default they are created active so if we need to change the status it should be done if not active
		if ldapImportConf.User.Status.Value != "active" {
			return true
		}
	}

	return false
}
func checkUserNeedsStatusUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {

	if ldapImportConf.User.Status.Action == "Both" || ldapImportConf.User.Status.Action == "Update" {
		//-- Check current status != config status
		if HornbillUserStatusMap[currentData.HAccountStatus] != ldapImportConf.User.Status.Value {
			return true
		}
	}
	return false
}
func setUserPasswordValueForCreate(importData *userWorkingDataStruct) {
	if importData.Account.Password == "" {
		//-- Generate Password
		importData.Account.Password = generatePasswordString(importData)
		logger(1, "Auto Generated Password for: "+importData.Jobs.id+" - "+importData.Account.Password, false)
	}
	//-- Base64 Encode
	importData.Account.Password = base64.StdEncoding.EncodeToString([]byte(importData.Account.Password))
}
func checkUserNeedsOrgRemoving(importData *userWorkingDataStruct, currentData userAccountStruct) {
	//-- Only if we have some config for groups
	if len(ldapImportConf.User.Org) > 0 {

		//-- List of Existing Groups
		var userExistingGroups = HornbillCache.UserGroups[strings.ToLower(importData.Jobs.id)]

		for index := range userExistingGroups {
			ExistingGroupID := userExistingGroups[index]
			ExistingGroup := HornbillCache.GroupsID[strings.ToLower(ExistingGroupID)]
			boolGroupNeedsRemoving := false

			//-- Loop Config Orgs and Check each one
			for orgIndex := range ldapImportConf.User.Org {

				//-- Get Group from Index
				importOrg := ldapImportConf.User.Org[orgIndex]

				//-- Only if Actions is correct
				if importOrg.Action == "Both" || importOrg.Action == "Update" {
					//-- Evaluate the Id
					var GroupID = getOrgFromLookup(importData, importOrg.Value, importOrg.Options.Type)
					//-- If already a member of import group then ignore
					if GroupID == ExistingGroup.ID {
						//-- exit for loop
						continue
					}

					//-- If group we are a memember of matches the Type of a group we have set up on the import and its set to one Assignment
					if importOrg.Options.Type == ExistingGroup.Type && importOrg.Options.OnlyOneGroupAssignment {
						boolGroupNeedsRemoving = true
					}
				}
			}
			//-- If group is not part of import and its set to remove
			if boolGroupNeedsRemoving {
				importData.GroupsToRemove = append(importData.GroupsToRemove, ExistingGroupID)
			}
		}
	}
}

func checkUserNeedsOrgUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) {
	if len(ldapImportConf.User.Org) > 0 {
		for orgIndex := range ldapImportConf.User.Org {
			orgAction := ldapImportConf.User.Org[orgIndex]
			if orgAction.Action == "Both" || orgAction.Action == "Update" {
				var GroupID = getOrgFromLookup(importData, orgAction.Value, orgAction.Options.Type)
				var userExistingGroups = HornbillCache.UserGroups[strings.ToLower(importData.Jobs.id)]
				//-- Is User Already a Memeber of the Group
				boolUserInGroup := false
				for index := range userExistingGroups {
					if strings.EqualFold(GroupID, userExistingGroups[index]) {
						boolUserInGroup = true
					}
				}
				if !boolUserInGroup && GroupID != "" {
					//-- Check User is a member of
					if orgAction.MemberOf != "" {
						if !isUserAMember(importData.LDAP, orgAction.MemberOf) {
							continue
						}
					}
					var group userGroupStruct
					group.ID = GroupID
					group.Name = orgAction.Value
					group.Type = orgAction.Options.Type
					group.Membership = orgAction.Options.Membership
					group.TasksView = orgAction.Options.TasksView
					group.TasksAction = orgAction.Options.TasksAction
					group.OnlyOneGroupAssignment = orgAction.Options.OnlyOneGroupAssignment

					importData.Groups = append(importData.Groups, group)
				}
			}
		}
	}
}

func checkUserNeedsHomeOrgUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	if len(ldapImportConf.User.Org) > 0 {
		for orgIndex := range ldapImportConf.User.Org {
			orgAction := ldapImportConf.User.Org[orgIndex]
			if !orgAction.Options.SetAsHomeOrganisation {
				continue
			}
			if orgAction.Action == "Create" || orgAction.Action == "Both" || orgAction.Action == "Update" {
				var GroupID = getOrgFromLookup(importData, orgAction.Value, orgAction.Options.Type)

				if GroupID == "" || strings.EqualFold(currentData.HHomeOrg, GroupID) {
					return false
				}
				importData.Account.HomeOrg = GroupID
				logger(1, "Home Organisation: "+GroupID+" - "+currentData.HHomeOrg, true)
				return true
			}
		}
	}
	return false
}

func checkUserNeedsOrgCreate(importData *userWorkingDataStruct, currentData userAccountStruct) {
	if len(ldapImportConf.User.Org) > 0 {
		for orgIndex := range ldapImportConf.User.Org {
			orgAction := ldapImportConf.User.Org[orgIndex]
			if orgAction.Action == "Both" || orgAction.Action == "Create" {

				var GroupID = getOrgFromLookup(importData, orgAction.Value, orgAction.Options.Type)

				if GroupID != "" && orgAction.MemberOf != "" {
					if !isUserAMember(importData.LDAP, orgAction.MemberOf) {
						continue
					}
				}
				var group userGroupStruct
				group.ID = GroupID
				group.Name = orgAction.Value
				group.Type = orgAction.Options.Type
				group.Membership = orgAction.Options.Membership
				group.TasksView = orgAction.Options.TasksView
				group.TasksAction = orgAction.Options.TasksAction
				group.OnlyOneGroupAssignment = orgAction.Options.OnlyOneGroupAssignment

				if GroupID != "" {
					importData.Groups = append(importData.Groups, group)
				}
			}
		}
	}
}
func setUserRolesalueForCreate(importData *userWorkingDataStruct, currentData userAccountStruct) {

	if ldapImportConf.User.Role.Action == "Both" || ldapImportConf.User.Role.Action == "Create" {
		importData.Roles = ldapImportConf.User.Role.Roles
	}
}
func checkUserNeedsRoleUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) {

	if ldapImportConf.User.Role.Action == "Both" || ldapImportConf.User.Role.Action == "Update" {
		for index := range ldapImportConf.User.Role.Roles {
			roleName := ldapImportConf.User.Role.Roles[index]
			foundRole := false
			var userRoles = HornbillCache.UserRoles[strings.ToLower(importData.Jobs.id)]
			for index2 := range userRoles {
				if strings.EqualFold(roleName, userRoles[index2]) {
					foundRole = true
				}
			}
			if !foundRole {
				importData.Roles = append(importData.Roles, roleName)
			}
		}
	}
}
func checkUserNeedsImageCreate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	//-- Is Type Enables for Update or both
	if ldapImportConf.User.Image.Action == "Both" || ldapImportConf.User.Image.Action == "Create" {

		//-- Check for Empty URI
		if ldapImportConf.User.Image.URI == "" {
			return false
		}
		image := getImage(importData)
		// check for changes
		if image.imageCheckSum != currentData.HIconChecksum {
			return true
		}
	}
	return false
}
func checkUserNeedsImageUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	//-- Is Type Enables for Update or both
	if ldapImportConf.User.Image.Action == "Both" || ldapImportConf.User.Image.Action == "Update" {

		//-- Check for Empty URI
		if ldapImportConf.User.Image.URI == "" {
			return false
		}
		//-- If URI is __clear__ and there's no icon, we don't want to try to update the icon
		if strings.EqualFold(ldapImportConf.User.Image.URI, "__clear__") && currentData.HIconRef == "" {
			return false
		}
		image := getImage(importData)
		// check for changes
		if image.imageCheckSum != currentData.HIconChecksum {
			return true
		}
	}
	return false
}
func checkUserNeedsTypeUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	//-- Is Type Enables for Update or both
	if ldapImportConf.User.Type.Action == "Both" || ldapImportConf.User.Type.Action == "Update" {
		// -- 1 = user
		// -- 3 = basic
		switch importData.Account.UserType {
		case "user":
			if currentData.HClass != "1" {
				return true
			}
		case "basic":
			if currentData.HClass != "3" {
				return true
			}
		default:
			return false
		}
	} else {
		if currentData.HClass == "1" {
			importData.Account.UserType = "user"
		} else {
			importData.Account.UserType = "basic"
		}
	}
	return false
}
func setUserSiteValueForCreate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	//-- Is Site Enables for Update or both
	if ldapImportConf.User.Site.Action == "Both" || ldapImportConf.User.Site.Action == "Create" {
		importData.Account.Site = getSiteFromLookup(importData)
	}
	if importData.Account.Site != "" && importData.Account.Site != currentData.HSite {
		return true
	}
	return false
}
func checkUserNeedsSiteUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	if strings.EqualFold(importData.Account.Site, "__clear__") {
		if currentData.HSite == "0" || currentData.HSite == "" {
			return false
		} else {
			return true
		}
	}

	//-- Is Site Enabled for Update or both
	if ldapImportConf.User.Site.Action == "Both" || ldapImportConf.User.Site.Action == "Update" {
		importData.Account.Site = getSiteFromLookup(importData)
	} else {
		//-- Else Default to current value
		importData.Account.Site = currentData.HSite
	}

	if importData.Account.Site != "" && importData.Account.Site != currentData.HSite {
		return true
	}
	return false
}
func checkUserNeedsUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	userUpdate := false
	if importData.Account.LoginID != "" && importData.Account.LoginID != currentData.HLoginID {
		logger(1, "LoginID: "+importData.Account.LoginID+" - "+currentData.HLoginID, true)
		userUpdate = true
	} else if importData.Account.LoginID == currentData.HLoginID {
		importData.Account.LoginID = "hornbillLoginIDDeDup"
	}
	if checkUserFieldUpdate(importData.Account.Name, currentData.HName) {
		logger(1, "Name: "+importData.Account.Name+" - "+currentData.HName, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.EmployeeID, currentData.HEmployeeID) {
		logger(1, "EmployeeID: "+importData.Account.EmployeeID+" - "+currentData.HEmployeeID, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.FirstName, currentData.HFirstName) {
		logger(1, "FirstName: "+importData.Account.FirstName+" - "+currentData.HFirstName, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.LastName, currentData.HLastName) {
		logger(1, "LastName: "+importData.Account.LastName+" - "+currentData.HLastName, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.JobTitle, currentData.HJobTitle) {
		logger(1, "JobTitle: "+importData.Account.JobTitle+" - "+currentData.HJobTitle, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.Phone, currentData.HPhone) {
		logger(1, "Phone: "+importData.Account.Phone+" - "+currentData.HPhone, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.Email, currentData.HEmail) {
		logger(1, "Email: "+importData.Account.Email+" - "+currentData.HEmail, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.Mobile, currentData.HMobile) {
		logger(1, "Mobile: "+importData.Account.Mobile+" - "+currentData.HMobile, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.AbsenceMessage, currentData.HAvailStatusMsg) {
		logger(1, "AbsenceMessage: "+importData.Account.AbsenceMessage+" - "+currentData.HAvailStatusMsg, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.TimeZone, currentData.HTimezone) {
		logger(1, "TimeZone: "+importData.Account.TimeZone+" - "+currentData.HTimezone, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.Language, currentData.HLanguage) {
		logger(1, "Language: "+importData.Account.Language+" - "+currentData.HLanguage, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.DateTimeFormat, currentData.HDateTimeFormat) {
		logger(1, "DateTimeFormat: "+importData.Account.DateTimeFormat+" - "+currentData.HDateTimeFormat, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.DateFormat, currentData.HDateFormat) {
		logger(1, "DateFormat: "+importData.Account.DateFormat+" - "+currentData.HDateFormat, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.TimeFormat, currentData.HTimeFormat) {
		logger(1, "TimeFormat: "+importData.Account.TimeFormat+" - "+currentData.HTimeFormat, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.CurrencySymbol, currentData.HCurrencySymbol) {
		logger(1, "CurrencySymbol: "+importData.Account.CurrencySymbol+" - "+currentData.HCurrencySymbol, true)
		userUpdate = true
	}
	if checkUserFieldUpdate(importData.Account.CountryCode, currentData.HCountry) {
		logger(1, "CountryCode: "+importData.Account.CountryCode+" - "+currentData.HCountry, true)
		userUpdate = true
	}
	val, ok := twoFAMap[currentData.HLogon2FAMethod]

	if ok {
		if checkUserFieldUpdate(importData.Account.Enable2FA, val) {
			logger(1, "Enable2FA: "+importData.Account.Enable2FA+" - "+val, true)
			userUpdate = true
		}
	}
	userSecFlag := getUserFlag(importData.Account)
	if checkUserFieldUpdate(userSecFlag, currentData.HSecOptions) {
		userUpdate = true
		importData.Account.UpdateSecOptions = true
		importData.Account.SecurityFlag = userSecFlag
		logger(1, "SecurityOptionsFlag: "+userSecFlag+" - "+currentData.HSecOptions, true)
		logger(1, "DisableDirectLogin: "+importData.Account.DisableDirectLogin, true)
		logger(1, "DisableDirectLoginPasswordReset: "+importData.Account.DisableDirectLoginPasswordReset, true)
		logger(1, "DisableDevicePairing: "+importData.Account.DisableDevicePairing, true)
	}

	return userUpdate
}

func getUserFlag(account AccountMappingStruct) string {
	newFlag := 0
	if account.DisableDirectLogin == "true" {
		newFlag += 1
	}
	if account.DisableDirectLoginPasswordReset == "true" {
		newFlag += 2
	}
	if account.DisableDevicePairing == "true" {
		newFlag += 4
	}
	return strconv.Itoa(newFlag)
}

func checkUserFieldUpdate(importField, currentField string) bool {
	if strings.EqualFold(importField, "__clear__") && currentField == "" {
		return false
	} else if importField != "" && importField != currentField {
		return true
	}
	return false
}
func checkUserNeedsProfileUpdate(importData *userWorkingDataStruct, currentData userAccountStruct) bool {
	userProfileUpdate := false
	if ldapImportConf.User.Manager.Action == "Both" || ldapImportConf.User.Manager.Action == "Update" {
		importData.Profile.Manager = getManager(importData, currentData)
	} else {
		//-- Use Current Value
		importData.Profile.Manager = currentData.HManager
	}
	if checkUserFieldUpdate(importData.Profile.Manager, currentData.HManager) {
		logger(1, "Manager: "+importData.Profile.Manager+" - "+currentData.HManager, true)
		userProfileUpdate = true
	}

	if checkUserFieldUpdate(importData.Profile.MiddleName, currentData.HMiddleName) {
		logger(1, "MiddleName: "+importData.Profile.MiddleName+" - "+currentData.HMiddleName, true)
		userProfileUpdate = true
	}

	if checkUserFieldUpdate(importData.Profile.JobDescription, currentData.HSummary) {
		logger(1, "JobDescription: "+importData.Profile.JobDescription+" - "+currentData.HSummary, true)
		userProfileUpdate = true
	}
	//	if checkUserFieldUpdate(importData.Profile.WorkPhone, currentData.HPhone) {
	//		logger(1, "WorkPhone: "+importData.Profile.WorkPhone+" - "+currentData.HPhone, true)
	//		userProfileUpdate = true
	//	}
	if checkUserFieldUpdate(importData.Profile.Qualifications, currentData.HQualifications) {
		logger(1, "Qualifications: "+importData.Profile.Qualifications+" - "+currentData.HQualifications, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Interests, currentData.HInterests) {
		logger(1, "Interests: "+importData.Profile.Interests+" - "+currentData.HInterests, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Expertise, currentData.HSkills) {
		logger(1, "Expertise: "+importData.Profile.Expertise+" - "+currentData.HSkills, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Gender, currentData.HGender) {
		logger(1, "Gender: "+importData.Profile.Gender+" - "+currentData.HGender, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Dob, currentData.HDob) {
		logger(1, "Dob: "+importData.Profile.Dob+" - "+currentData.HDob, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Nationality, currentData.HNationality) {
		logger(1, "Nationality: "+importData.Profile.Nationality+" - "+currentData.HNationality, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Religion, currentData.HReligion) {
		logger(1, "Religion: "+importData.Profile.Religion+" - "+currentData.HReligion, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.HomeTelephone, currentData.HHomeTelephoneNumber) {
		logger(1, "HomeTelephone: "+importData.Profile.HomeTelephone+" - "+currentData.HHomeTelephoneNumber, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkA, currentData.HSnA) {
		logger(1, "SocialNetworkA: "+importData.Profile.SocialNetworkA+" - "+currentData.HSnA, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkB, currentData.HSnB) {
		logger(1, "SocialNetworkB: "+importData.Profile.SocialNetworkB+" - "+currentData.HSnB, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkC, currentData.HSnC) {
		logger(1, "SocialNetworkC: "+importData.Profile.SocialNetworkC+" - "+currentData.HSnC, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkD, currentData.HSnD) {
		logger(1, "SocialNetworkD: "+importData.Profile.SocialNetworkD+" - "+currentData.HSnD, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkE, currentData.HSnE) {
		logger(1, "SocialNetworkE: "+importData.Profile.SocialNetworkE+" - "+currentData.HSnE, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkF, currentData.HSnF) {
		logger(1, "SocialNetworkF: "+importData.Profile.SocialNetworkF+" - "+currentData.HSnF, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkG, currentData.HSnG) {
		logger(1, "SocialNetworkG: "+importData.Profile.SocialNetworkG+" - "+currentData.HSnG, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.SocialNetworkH, currentData.HSnH) {
		logger(1, "SocialNetworkH: "+importData.Profile.SocialNetworkH+" - "+currentData.HSnH, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.PersonalInterests, currentData.HPersonalInterests) {
		logger(1, "PersonalInterests: "+importData.Profile.PersonalInterests+" - "+currentData.HPersonalInterests, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.HomeAddress, currentData.HHomeAddress) {
		logger(1, "HomeAddress: "+importData.Profile.HomeAddress+" - "+currentData.HHomeAddress, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.PersonalBlog, currentData.HBlog) {
		logger(1, "PersonalBlog: "+importData.Profile.PersonalBlog+" - "+currentData.HBlog, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib1, currentData.HAttrib1) {
		logger(1, "Attrib1: "+importData.Profile.Attrib1+" - "+currentData.HAttrib1, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib2, currentData.HAttrib2) {
		logger(1, "Attrib2: "+importData.Profile.Attrib2+" - "+currentData.HAttrib2, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib3, currentData.HAttrib3) {
		logger(1, "Attrib3: "+importData.Profile.Attrib3+" - "+currentData.HAttrib3, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib4, currentData.HAttrib4) {
		logger(1, "Attrib4: "+importData.Profile.Attrib4+" - "+currentData.HAttrib4, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib5, currentData.HAttrib5) {
		logger(1, "Attrib5: "+importData.Profile.Attrib5+" - "+currentData.HAttrib5, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib6, currentData.HAttrib6) {
		logger(1, "Attrib6: "+importData.Profile.Attrib6+" - "+currentData.HAttrib6, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib7, currentData.HAttrib7) {
		logger(1, "Attrib7: "+importData.Profile.Attrib7+" - "+currentData.HAttrib7, true)
		userProfileUpdate = true
	}
	if checkUserFieldUpdate(importData.Profile.Attrib8, currentData.HAttrib8) {
		logger(1, "Attrib8: "+importData.Profile.Attrib8+" - "+currentData.HAttrib8, true)
		userProfileUpdate = true
	}
	return userProfileUpdate
}

// -- For Each Import Actions process the data
func processImportActions(l *ldap.Entry) (userID string) {

	//-- Set User Account Attributes
	var data = new(userWorkingDataStruct)
	data.LDAP = l
	//-- init map
	data.Custom = make(map[string]string)

	// -- Loop Matches
	for _, action := range ldapImportConf.Actions {
		switch action.Action {
		case "Regex":
			//-- Grab value from LDAP
			Outcome := processComplexField(l, action.Value, true)
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, true)
			//-- Process Regex
			Outcome = processRegexOnString(action.Options.RegexValue, Outcome)
			//-- Store
			data.Custom["{"+action.Output+"}"] = Outcome

			logger(1, "Regex Output: "+Outcome, false)
		case "Replace":
			//-- Grab value from LDAP
			Outcome := processComplexField(l, action.Value, true)
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, true)
			//-- Run Replace
			Outcome = strings.Replace(Outcome, action.Options.ReplaceFrom, action.Options.ReplaceWith, -1)
			//-- Store
			data.Custom["{"+action.Output+"}"] = Outcome

			logger(1, "Replace Output: "+Outcome, false)
		case "Trim":
			//-- Grab value from LDAP
			Outcome := processComplexField(l, action.Value, true)
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, true)
			//-- Run Replace
			Outcome = strings.TrimSpace(Outcome)
			Outcome = strings.Replace(Outcome, "\n", "", -1)
			Outcome = strings.Replace(Outcome, "\r", "", -1)
			Outcome = strings.Replace(Outcome, "\r\n", "", -1)
			//-- Store
			data.Custom["{"+action.Output+"}"] = Outcome

			logger(1, "Trim Output: "+Outcome, false)
		case "LDAPDateToDateTime":
			//-- Grab value from LDAP
			Outcome := processComplexField(l, action.Value, true)
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, true)
			//-- Run Replace
			i, err := strconv.ParseInt(Outcome, 10, 64)
			if err != nil {
				logger(4, "LDAPDateToDateTime Action ParseInt Failed on : "+Outcome, false)
			} else {
				var t int64 = (i / 10000000) - 11644473600
				Outcome = time.Unix(t, 0).Format("2006-01-02 15:04:05")
			}
			//-- Store
			data.Custom["{"+action.Output+"}"] = Outcome

			logger(1, "LDAPDateToDateTime Output: "+Outcome, false)
		case "SIDConversion":
			//-- Grab value from LDAP
			Outcome := processComplexField(l, action.Value, false)
			OutcomeConverted := ""
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, false)
			if Outcome != "" {
				//-- Run Replace
				sid := objectsid.Decode([]byte(Outcome))
				OutcomeConverted = sid.String()
			}
			data.Custom["{"+action.Output+"}"] = OutcomeConverted
			logger(1, "SID Conversion Output, From: ["+fmt.Sprintf("%X", []byte(Outcome))+"] To: ["+OutcomeConverted+"]", false)
		case "GUIDConversion":
			//-- Grab value from LDAP
			Outcome := processComplexField(l, action.Value, false)
			OutcomeConverted := ""
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, false)
			if Outcome != "" {
				//-- Run Replace
				OutcomeConverted = convertToGUID([]byte(Outcome))
			}
			data.Custom["{"+action.Output+"}"] = OutcomeConverted

			logger(1, "ObjectGUID Conversion Output, From: ["+fmt.Sprintf("%X", []byte(Outcome))+"] To: ["+OutcomeConverted+"]", false)
		case "None":
			//-- Grab value
			Outcome := processComplexField(l, action.Value, true)
			//-- Grab Value from Existing Custom Field
			Outcome = processImportAction(data.Custom, Outcome, true)
			//-- Store
			data.Custom["{"+action.Output+"}"] = Outcome

			logger(1, "Copy Output: "+Outcome, false)

		default:
			logger(1, "Unknown Action: "+action.Action, false)
		}
	}

	data.Account.UserID = getUserFieldValue(l, "UserID", data.Custom)
	data.Account.CheckID = data.Account.UserID

	switch ldapImportConf.User.HornbillUserIDColumn {
	case "h_employee_id":
		{
			data.Account.CheckID = getUserFieldValue(l, "EmployeeID", data.Custom)
		}
	case "h_login_id":
		{
			data.Account.CheckID = getUserFieldValue(l, "LoginID", data.Custom)
		}
	case "h_email":
		{
			data.Account.CheckID = getUserFieldValue(l, "Email", data.Custom)
		}
	case "h_mobile":
		{
			data.Account.CheckID = getUserFieldValue(l, "Mobile", data.Custom)
		}
	case "h_attrib1":
		{
			data.Account.CheckID = getProfileFieldValue(l, "Attrib1", data.Custom)
		}
	case "h_attrib8":
		{
			data.Account.CheckID = getProfileFieldValue(l, "Attrib8", data.Custom)
		}
	case "h_sn_a":
		{
			data.Account.CheckID = getProfileFieldValue(l, "SocialNetworkA", data.Custom)
		}
	}

	if data.Account.CheckID == "" {
		logger(3, "No Unique Identifier set for this record: "+fmt.Sprintf("%v", l), true)
		return ""
	}
	logger(2, "Process Data for:  "+data.Account.CheckID+" ("+data.Account.UserID+")", false)

	logger(1, "Import Actions for: "+data.Account.UserID, false)

	//-- Store Result in map of userid
	userID = strings.ToLower(data.Account.CheckID)
	HornbillCache.UsersWorking[userID] = data
	return userID
}

// -- For Each LDAP User Process Account And Mappings
func processUserParams(l *ldap.Entry, userID string) {
	data := HornbillCache.UsersWorking[userID]
	data.Account.LoginID = getUserFieldValue(l, "LoginID", data.Custom)
	data.Account.EmployeeID = getUserFieldValue(l, "EmployeeID", data.Custom)
	data.Account.UserType = getUserFieldValue(l, "UserType", data.Custom)
	data.Account.Name = getUserFieldValue(l, "Name", data.Custom)
	data.Account.Password = getUserFieldValue(l, "Password", data.Custom)
	data.Account.FirstName = getUserFieldValue(l, "FirstName", data.Custom)
	data.Account.LastName = getUserFieldValue(l, "LastName", data.Custom)
	data.Account.JobTitle = getUserFieldValue(l, "JobTitle", data.Custom)
	data.Account.Site = getUserFieldValue(l, "Site", data.Custom)
	data.Account.Phone = getUserFieldValue(l, "Phone", data.Custom)
	if data.Account.Phone == "" {
		data.Account.Phone = getProfileFieldValue(l, "WorkPhone", data.Custom)
	}
	data.Account.Email = getUserFieldValue(l, "Email", data.Custom)
	data.Account.Mobile = getUserFieldValue(l, "Mobile", data.Custom)
	data.Account.AbsenceMessage = getUserFieldValue(l, "AbsenceMessage", data.Custom)
	data.Account.TimeZone = getUserFieldValue(l, "TimeZone", data.Custom)
	data.Account.Language = getUserFieldValue(l, "Language", data.Custom)
	data.Account.DateTimeFormat = getUserFieldValue(l, "DateTimeFormat", data.Custom)
	data.Account.DateFormat = getUserFieldValue(l, "DateFormat", data.Custom)
	data.Account.TimeFormat = getUserFieldValue(l, "TimeFormat", data.Custom)
	data.Account.CurrencySymbol = getUserFieldValue(l, "CurrencySymbol", data.Custom)
	data.Account.CountryCode = getUserFieldValue(l, "CountryCode", data.Custom)
	data.Account.Enable2FA = getUserFieldValue(l, "Enable2FA", data.Custom)
	data.Account.DisableDirectLogin = getUserFieldValue(l, "DisableDirectLogin", data.Custom)
	data.Account.DisableDirectLoginPasswordReset = getUserFieldValue(l, "DisableDirectLoginPasswordReset", data.Custom)
	data.Account.DisableDevicePairing = getUserFieldValue(l, "DisableDevicePairing", data.Custom)
	data.Profile.MiddleName = getProfileFieldValue(l, "MiddleName", data.Custom)
	data.Profile.JobDescription = getProfileFieldValue(l, "JobDescription", data.Custom)
	data.Profile.Manager = getProfileFieldValue(l, "Manager", data.Custom)
	//	data.Profile.WorkPhone = getProfileFieldValue(l, "WorkPhone", data.Custom)
	data.Profile.Qualifications = getProfileFieldValue(l, "Qualifications", data.Custom)
	data.Profile.Interests = getProfileFieldValue(l, "Interests", data.Custom)
	data.Profile.Expertise = getProfileFieldValue(l, "Expertise", data.Custom)
	data.Profile.Gender = getProfileFieldValue(l, "Gender", data.Custom)
	data.Profile.Dob = getProfileFieldValue(l, "Dob", data.Custom)
	data.Profile.Nationality = getProfileFieldValue(l, "Nationality", data.Custom)
	data.Profile.Religion = getProfileFieldValue(l, "Religion", data.Custom)
	data.Profile.HomeTelephone = getProfileFieldValue(l, "HomeTelephone", data.Custom)
	data.Profile.SocialNetworkA = getProfileFieldValue(l, "SocialNetworkA", data.Custom)
	data.Profile.SocialNetworkB = getProfileFieldValue(l, "SocialNetworkB", data.Custom)
	data.Profile.SocialNetworkC = getProfileFieldValue(l, "SocialNetworkC", data.Custom)
	data.Profile.SocialNetworkD = getProfileFieldValue(l, "SocialNetworkD", data.Custom)
	data.Profile.SocialNetworkE = getProfileFieldValue(l, "SocialNetworkE", data.Custom)
	data.Profile.SocialNetworkF = getProfileFieldValue(l, "SocialNetworkF", data.Custom)
	data.Profile.SocialNetworkG = getProfileFieldValue(l, "SocialNetworkG", data.Custom)
	data.Profile.SocialNetworkH = getProfileFieldValue(l, "SocialNetworkH", data.Custom)
	data.Profile.PersonalInterests = getProfileFieldValue(l, "PersonalInterests", data.Custom)
	data.Profile.HomeAddress = getProfileFieldValue(l, "HomeAddress", data.Custom)
	data.Profile.PersonalBlog = getProfileFieldValue(l, "PersonalBlog", data.Custom)
	data.Profile.Attrib1 = getProfileFieldValue(l, "Attrib1", data.Custom)
	data.Profile.Attrib2 = getProfileFieldValue(l, "Attrib2", data.Custom)
	data.Profile.Attrib3 = getProfileFieldValue(l, "Attrib3", data.Custom)
	data.Profile.Attrib4 = getProfileFieldValue(l, "Attrib4", data.Custom)
	data.Profile.Attrib5 = getProfileFieldValue(l, "Attrib5", data.Custom)
	data.Profile.Attrib6 = getProfileFieldValue(l, "Attrib6", data.Custom)
	data.Profile.Attrib7 = getProfileFieldValue(l, "Attrib7", data.Custom)
	data.Profile.Attrib8 = getProfileFieldValue(l, "Attrib8", data.Custom)
}

func convertToGUID(objectGUID []byte) string {
	if len(objectGUID) < 16 {
		return ""
	}
	output := ""
	output += fmt.Sprintf("%02X", int64(objectGUID[3]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[2]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[1]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[0]&0xFF))
	output += "-"
	output += fmt.Sprintf("%02X", int64(objectGUID[5]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[4]&0xFF))
	output += "-"
	output += fmt.Sprintf("%02X", int64(objectGUID[7]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[6]&0xFF))
	output += "-"
	output += fmt.Sprintf("%02X", int64(objectGUID[8]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[9]&0xFF))
	output += "-"
	output += fmt.Sprintf("%02X", int64(objectGUID[10]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[11]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[12]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[13]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[14]&0xFF))
	output += fmt.Sprintf("%02X", int64(objectGUID[15]&0xFF))

	return output
}
