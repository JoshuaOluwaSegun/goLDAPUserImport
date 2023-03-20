package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	apiLib "github.com/hornbill/goApiLib"
	"github.com/hornbill/pb"
)

var (
	hornbillImport *apiLib.XmlmcInstStruct
	pageSize       int
)

func initXMLMC() {
	hornbillImport = apiLib.NewXmlmcInstance(Flags.configInstanceID)
	hornbillImport.SetAPIKey(Flags.configAPIKey)
	hornbillImport.SetTimeout(Flags.configAPITimeout)
	hornbillImport.SetJSONResponse(true)

	pageSize = ldapImportConf.Advanced.PageSize

	if pageSize == 0 {
		pageSize = 100
	}
}
func loadUsers() {
	//-- Init One connection to Hornbill to load all data
	initXMLMC()
	logger(1, "Loading Users from Hornbill", false)

	count := getCount("getUserAccountsList")
	logger(1, "getUserAccountsList Count: "+fmt.Sprintf("%d", count), false)
	if !Flags.configSkipCache {
		getUserAccountList(count)
	}

	logger(1, "Users Loaded: "+fmt.Sprintf("%d", len(HornbillCache.Users)), false)
}
func loadUsersRoles() {
	//-- Only Load if Enabled
	if ldapImportConf.User.Role.Action != "Create" && ldapImportConf.User.Role.Action != "Update" && ldapImportConf.User.Role.Action != "Both" {
		logger(1, "Skipping Loading Roles Due to Config", false)
		return
	}

	logger(1, "Loading Users Roles from Hornbill", false)

	count := getCount("getUserAccountsRolesList")
	logger(1, "getUserAccountsRolesList Count: "+fmt.Sprintf("%d", count), false)
	if !Flags.configSkipCache {
		getUserAccountsRolesList(count)
	}

	logger(1, "Users Roles Loaded: "+fmt.Sprintf("%d", len(HornbillCache.UserRoles)), false)
}

func loadSites() {
	//-- Only Load if Enabled
	if ldapImportConf.User.Site.Action != "Create" && ldapImportConf.User.Site.Action != "Update" && ldapImportConf.User.Site.Action != "Both" {
		logger(1, "Skipping Loading Sites Due to Config", false)
		return
	}

	logger(1, "Loading Sites from Hornbill", false)

	count := getCount("getSitesList")
	logger(1, "getSitesList Count: "+fmt.Sprintf("%d", count), false)
	getSitesList(count)

	logger(1, "Sites Loaded: "+fmt.Sprintf("%d", len(HornbillCache.Sites)), false)
}
func loadGroups() {
	boolSkip := true
	for index := range ldapImportConf.User.Org {
		orgAction := ldapImportConf.User.Org[index]
		if orgAction.Action == "Create" || orgAction.Action == "Update" || orgAction.Action == "Both" {
			boolSkip = false
		}
	}
	if boolSkip {
		logger(1, "Skipping Loading Orgs Due to Config", false)
		return
	}
	//-- Only Load if Enabled
	logger(1, "Loading Orgs from Hornbill", false)

	count := getCount("getGroupsList")
	logger(1, "getGroupsList Count: "+fmt.Sprintf("%d", count), false)
	getGroupsList(count)

	logger(1, "Orgs Loaded: "+fmt.Sprintf("%d", len(HornbillCache.GroupsID)), false)
}
func loadUserGroups() {
	boolSkip := true
	for index := range ldapImportConf.User.Org {
		orgAction := ldapImportConf.User.Org[index]
		if orgAction.Action == "Create" || orgAction.Action == "Update" || orgAction.Action == "Both" {
			boolSkip = false
		}
	}
	if boolSkip {
		logger(1, "Skipping Loading User Orgs Due to Config", false)
		return
	}
	//-- Only Load if Enabled
	logger(1, "Loading User Orgs from Hornbill", false)

	count := getCount("getUserAccountsGroupsListImport")
	userAccountRecordCount := getUserAccountsGroupsList(count)
	logger(1, "User Orgs Loaded: "+fmt.Sprintf("%d", userAccountRecordCount)+"\n", false)
}

// -- Check so that only data that relates to users in the LDAP data set are stored in the working set
func userIDExistsInLDAP(userID string) bool {
	userID = strings.ToLower(userID)
	_, present := HornbillCache.UsersWorking[userID]
	return present
}

func getUserAccountsGroupsList(count uint64) (recordCount int64) {
	var loopCount uint64
	if Flags.configSkipCache {
		return
	}
	//-- Init Map
	HornbillCache.UserGroups = make(map[string][]string)
	bar := pb.StartNew(int(count))
	previousUser := ""
	previousGroup := ""
	//-- Load Results in pages of pageSize
	for loopCount < count {
		logger(1, "Loading User Accounts Orgs List Offset: "+fmt.Sprintf("%d", loopCount), false)

		hornbillImport.SetParam("application", "com.hornbill.core")
		hornbillImport.SetParam("queryName", "getUserAccountsGroupsListImport")
		hornbillImport.OpenElement("queryParams")
		hornbillImport.SetParam("limit", strconv.Itoa(pageSize))
		if previousUser != "" && previousGroup != "" {
			hornbillImport.SetParam("previousRecordUserId", previousUser)
			hornbillImport.SetParam("previousRecordGroupId", previousGroup)
		}
		hornbillImport.CloseElement("queryParams")
		RespBody, xmlmcErr := hornbillImport.Invoke("data", "queryExec")

		var JSONResp xmlmcUserGroupListResponse
		if xmlmcErr != nil {
			logger(4, "Unable to Query Accounts Orgs List "+xmlmcErr.Error(), false)
			break
		}
		err := json.Unmarshal([]byte(RespBody), &JSONResp)
		if err != nil {
			logger(4, "Unable to Query Accounts Orgs  List "+err.Error(), false)
			break
		}
		if JSONResp.State.Error != "" {
			logger(4, "Unable to Query Accounts Orgs  List "+JSONResp.State.Error, false)
			break
		}

		//-- Push into Map of slices to userId = array of roles
		for index := range JSONResp.Params.RowData.Row {
			if userIDExistsInLDAP(JSONResp.Params.RowData.Row[index].HUserID) {
				HornbillCache.UserGroups[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)] = append(HornbillCache.UserGroups[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)], JSONResp.Params.RowData.Row[index].HGroupID)
				recordCount++
			}
		}
		previousUser = JSONResp.Params.RowData.Row[len(JSONResp.Params.RowData.Row)-1].HUserID
		previousGroup = JSONResp.Params.RowData.Row[len(JSONResp.Params.RowData.Row)-1].HGroupID
		// Add loopcount
		loopCount += uint64(pageSize)
		bar.Add(len(JSONResp.Params.RowData.Row))
		//-- Check for empty result set
		if len(JSONResp.Params.RowData.Row) == 0 {
			break
		}
	}
	bar.FinishPrint("Account Orgs Loaded \n")
	return
}
func getGroupsList(count uint64) {
	var loopCount uint64
	//-- Init Map
	HornbillCache.Groups = make(map[string]userGroupStruct)
	HornbillCache.GroupsID = make(map[string]userGroupStruct)
	//-- Load Results in pages of pageSize
	bar := pb.StartNew(int(count))
	for loopCount < count {
		logger(1, "Loading Orgs List Offset: "+fmt.Sprintf("%d", loopCount), false)

		hornbillImport.SetParam("application", "com.hornbill.core")
		hornbillImport.SetParam("queryName", "getGroupsList")
		hornbillImport.OpenElement("queryParams")
		hornbillImport.SetParam("rowstart", strconv.FormatUint(loopCount, 10))
		hornbillImport.SetParam("limit", strconv.Itoa(pageSize))
		hornbillImport.CloseElement("queryParams")
		RespBody, xmlmcErr := hornbillImport.Invoke("data", "queryExec")

		var JSONResp xmlmcGroupListResponse
		if xmlmcErr != nil {
			logger(4, "Unable to Query Orgs List "+xmlmcErr.Error(), false)
			break
		}
		err := json.Unmarshal([]byte(RespBody), &JSONResp)
		if err != nil {
			logger(4, "Unable to Query Orgs List "+err.Error(), false)
			break
		}
		if JSONResp.State.Error != "" {
			logger(4, "Unable to Query Orgs List "+JSONResp.State.Error, false)
			break
		}

		//-- Push into Map
		for _, rec := range JSONResp.Params.RowData.Row {
			var group userGroupStruct
			group.ID = rec.HID
			group.Name = rec.HName
			group.Type, _ = strconv.Atoi(rec.HType)

			//-- List of group names to group object for name to id lookup
			HornbillCache.Groups[strings.ToLower(rec.HName)] = group
			//-- List of group id to group objects for id to type lookup
			HornbillCache.GroupsID[strings.ToLower(rec.HID)] = group
		}
		// Add 100
		loopCount += uint64(pageSize)
		bar.Add(len(JSONResp.Params.RowData.Row))
		//-- Check for empty result set
		if len(JSONResp.Params.RowData.Row) == 0 {
			break
		}
	}
	bar.FinishPrint("Orgs Loaded  \n")
}

func getUserAccountsRolesList(count uint64) {
	var loopCount uint64

	//-- Init Map
	HornbillCache.UserRoles = make(map[string][]string)
	bar := pb.StartNew(int(count))
	//-- Load Results in pages of pageSize
	for loopCount < count {
		logger(1, "Loading User Accounts Roles List Offset: "+fmt.Sprintf("%d", loopCount), false)

		hornbillImport.SetParam("application", "com.hornbill.core")
		hornbillImport.SetParam("queryName", "getUserAccountsRolesList")
		hornbillImport.OpenElement("queryParams")
		hornbillImport.SetParam("rowstart", strconv.FormatUint(loopCount, 10))
		hornbillImport.SetParam("limit", strconv.Itoa(pageSize))
		hornbillImport.CloseElement("queryParams")
		RespBody, xmlmcErr := hornbillImport.Invoke("data", "queryExec")

		var JSONResp xmlmcUserRolesListResponse
		if xmlmcErr != nil {
			logger(4, "Unable to Query Accounts Roles List "+xmlmcErr.Error(), false)
			break
		}
		err := json.Unmarshal([]byte(RespBody), &JSONResp)
		if err != nil {
			logger(4, "Unable to Query Accounts Roles  List "+err.Error(), false)
			break
		}
		if JSONResp.State.Error != "" {
			logger(4, "Unable to Query Accounts Roles  List "+JSONResp.State.Error, false)
			break
		}

		//-- Push into Map of slices to userId = array of roles
		for index := range JSONResp.Params.RowData.Row {
			if userIDExistsInLDAP(JSONResp.Params.RowData.Row[index].HUserID) {
				HornbillCache.UserRoles[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)] = append(HornbillCache.UserRoles[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)], JSONResp.Params.RowData.Row[index].HRole)
			}
		}
		// Add 100
		loopCount += uint64(pageSize)
		bar.Add(len(JSONResp.Params.RowData.Row))
		//-- Check for empty result set
		if len(JSONResp.Params.RowData.Row) == 0 {
			break
		}
	}
	bar.FinishPrint("Account Roles Loaded  \n")
}
func getUserAccountList(count uint64) {
	var loopCount uint64
	//-- Init Map
	HornbillCache.Users = make(map[string]userAccountStruct)
	//-- Load Results in pages of pageSize
	bar := pb.StartNew(int(count))
	for loopCount < count {
		logger(1, "Loading User Accounts List Offset: "+fmt.Sprintf("%d", loopCount)+"\n", false)

		hornbillImport.SetParam("application", "com.hornbill.core")
		hornbillImport.SetParam("queryName", "getUserAccountsList")
		hornbillImport.OpenElement("queryParams")
		hornbillImport.SetParam("rowstart", strconv.FormatUint(loopCount, 10))
		hornbillImport.SetParam("limit", strconv.Itoa(pageSize))
		hornbillImport.CloseElement("queryParams")
		RespBody, xmlmcErr := hornbillImport.Invoke("data", "queryExec")

		var JSONResp xmlmcUserListResponse
		if xmlmcErr != nil {
			logger(4, "Unable to Query Accounts List "+xmlmcErr.Error(), false)
			break
		}
		err := json.Unmarshal([]byte(RespBody), &JSONResp)
		if err != nil {
			logger(4, "Unable to Query Accounts List "+err.Error(), false)
			break
		}
		if JSONResp.State.Error != "" {
			logger(4, "Unable to Query Accounts List "+JSONResp.State.Error, false)
			break
		}
		//-- Push into Map
		//-- Store All Users so we can search later for manager on HName
		//-- This is better than calling back to the instance
		switch ldapImportConf.User.HornbillUserIDColumn {
		case "":
			{ // as Go Switch doesn't fall through
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_user_id":
			{ // as Go Switch doesn't fall through
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_employee_id":
			{
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HEmployeeID)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_login_id":
			{
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HLoginID)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_email":
			{
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HEmail)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_mobile":
			{ // as Go Switch doesn't fall through
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HMobile)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_attrib1":
			{ // as Go Switch doesn't fall through
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HAttrib1)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_attrib8":
			{ // as Go Switch doesn't fall through
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HAttrib8)] = JSONResp.Params.RowData.Row[index]
				}
			}
		case "h_sn_a":
			{ // as Go Switch doesn't fall through
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HSnA)] = JSONResp.Params.RowData.Row[index]
				}
			}
		default:
			{
				for index := range JSONResp.Params.RowData.Row {
					HornbillCache.Users[strings.ToLower(JSONResp.Params.RowData.Row[index].HUserID)] = JSONResp.Params.RowData.Row[index]
				}
			}
		}

		// Add pageSize
		loopCount += uint64(pageSize)
		bar.Add(len(JSONResp.Params.RowData.Row))
		//-- Check for empty result set
		if len(JSONResp.Params.RowData.Row) == 0 {
			break
		}
	}
	bar.FinishPrint("Accounts Loaded  \n")
}

func getSitesList(count uint64) {
	var loopCount uint64
	//-- Init Map
	HornbillCache.Sites = make(map[string]siteStruct)
	//-- Load Results in pages of pageSize
	bar := pb.StartNew(int(count))
	for loopCount < count {
		logger(1, "Loading Sites List Offset: "+fmt.Sprintf("%d", loopCount), false)

		hornbillImport.SetParam("application", "com.hornbill.core")
		hornbillImport.SetParam("queryName", "getSitesList")
		hornbillImport.OpenElement("queryParams")
		hornbillImport.SetParam("rowstart", strconv.FormatUint(loopCount, 10))
		hornbillImport.SetParam("limit", strconv.Itoa(pageSize))
		hornbillImport.CloseElement("queryParams")
		RespBody, xmlmcErr := hornbillImport.Invoke("data", "queryExec")

		var JSONResp xmlmcSiteListResponse
		if xmlmcErr != nil {
			logger(4, "Unable to Query Site List "+xmlmcErr.Error(), false)
			break
		}
		err := json.Unmarshal([]byte(RespBody), &JSONResp)
		if err != nil {
			logger(4, "Unable to Query Site List "+err.Error(), false)
			break
		}
		if JSONResp.State.Error != "" {
			logger(4, "Unable to Query Site List "+JSONResp.State.Error, false)
			break
		}

		//-- Push into Map
		for index := range JSONResp.Params.RowData.Row {
			HornbillCache.Sites[strings.ToLower(JSONResp.Params.RowData.Row[index].HSiteName)] = JSONResp.Params.RowData.Row[index]
		}
		// Add pageSize
		loopCount += uint64(pageSize)
		bar.Add(len(JSONResp.Params.RowData.Row))
		//-- Check for empty result set
		if len(JSONResp.Params.RowData.Row) == 0 {
			break
		}
	}
	bar.FinishPrint("Sites Loaded  \n")

}
func getCount(query string) uint64 {
	hornbillImport.SetParam("application", "com.hornbill.core")
	hornbillImport.SetParam("queryName", query)
	hornbillImport.OpenElement("queryParams")
	hornbillImport.SetParam("getCount", "true")
	hornbillImport.CloseElement("queryParams")
	logger(1, hornbillImport.GetParam(), false)
	RespBody, xmlmcErr := hornbillImport.Invoke("data", "queryExec")

	var JSONResp xmlmcCountResponse
	if xmlmcErr != nil {
		logger(4, "Unable to run Query ["+query+"] "+xmlmcErr.Error(), false)
		logger(1, RespBody, false)
		return 0
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		logger(4, "Unable to run Query ["+query+"] "+err.Error(), false)
		logger(1, RespBody, false)
		return 0
	}
	if JSONResp.State.Error != "" {
		logger(4, "Unable to run Query ["+query+"] "+JSONResp.State.Error, false)
		logger(1, RespBody, false)
		return 0
	}

	//-- return Count
	count, errC := strconv.ParseUint(JSONResp.Params.RowData.Row[0].Count, 10, 64)
	if errC != nil {
		logger(4, "Unable to get Count for Query ["+query+"] "+errC.Error(), false)
		logger(1, RespBody, false)
		return 0
	}
	return count
}

// getPasswordProfile - retrieves the user password profile settings from your Hornbill instance, applies ready for the password generator to use
func getPasswordProfile() {
	mc := apiLib.NewXmlmcInstance(Flags.configInstanceID)
	mc.SetAPIKey(Flags.configAPIKey)
	mc.SetTimeout(Flags.configAPITimeout)
	mc.SetJSONResponse(true)
	mc.SetParam("filter", "security.user.passwordPolicy")
	RespBody, xmlmcErr := mc.Invoke("admin", "sysOptionGet")
	var JSONResp xmlmcSettingResponse
	if xmlmcErr != nil {
		logger(4, "Unable to run sysOptionGet "+xmlmcErr.Error(), false)
		return
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		logger(4, "Unable to unmarshal sysOptionGet response "+err.Error(), false)
		return
	}
	if JSONResp.State.Error != "" {
		logger(4, "Error returned from sysOptionGet "+JSONResp.State.Error, false)
		return
	}
	//Process Password Profile
	//--Work through profile settings
	for _, val := range JSONResp.Params.Option {
		switch val.Key {
		case "security.user.passwordPolicy.checkBlacklists":
			passwordProfile.Blacklist = processBlacklists()
		case "security.user.passwordPolicy.checkPersonalInfo":
			passwordProfile.CheckMustNotContain, _ = strconv.ParseBool(val.Value)
		case "security.user.passwordPolicy.minimumLength":
			if val.Value == "0" {
				passwordProfile.Length = defaultPasswordLength
			} else {
				passwordProfile.Length, _ = strconv.Atoi(val.Value)
			}
		case "security.user.passwordPolicy.mustContainLowerCase":
			passwordProfile.ForceLower, _ = strconv.Atoi(val.Value)
		case "security.user.passwordPolicy.mustContainNumeric":
			passwordProfile.ForceNumeric, _ = strconv.Atoi(val.Value)
		case "security.user.passwordPolicy.mustContainSpecial":
			passwordProfile.ForceSpecial, _ = strconv.Atoi(val.Value)
		case "security.user.passwordPolicy.mustContainUpperCase":
			passwordProfile.ForceUpper, _ = strconv.Atoi(val.Value)
		}
	}
}

func processBlacklists() []string {
	var blacklist []string
	for _, v := range blacklistURLs {
		blacklistContent := getBlacklist(v)
		for _, l := range blacklistContent {
			alreadyInList := false
			for _, m := range blacklist {
				if strings.EqualFold(m, l) {
					alreadyInList = true
				}
			}
			if !alreadyInList {
				blacklist = append(blacklist, l)
			}
		}
	}
	return blacklist
}

func getBlacklist(blacklistURL string) []string {
	var blacklist []string
	//-- Get JSON Config
	response, err := http.Get(blacklistURL)
	if err != nil {
		logger(4, "Error Getting ["+blacklistURL+"] : "+err.Error(), false)
		return blacklist
	}
	if response.StatusCode != 200 {
		logger(4, "Unexpected status "+strconv.Itoa(response.StatusCode)+" returned from "+blacklistURL, false)
		return blacklist
	}
	//-- Close Connection
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	if err := scanner.Err(); err != nil {
		logger(4, "Unable to decode blacklist from "+blacklistURL+": "+err.Error(), false)
		return blacklist
	}
	for scanner.Scan() {
		textRow := scanner.Text()
		trimmedRow := strings.TrimSpace(textRow)
		//Ignore comment
		if string([]rune(trimmedRow)[0]) != "#" {
			blacklist = append(blacklist, trimmedRow)
		}
	}
	return blacklist
}
