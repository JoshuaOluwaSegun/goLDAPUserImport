package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	apiLib "github.com/hornbill/goApiLib"
	hornbillpasswordgen "github.com/hornbill/goHornbillPasswordGen"
	"github.com/hornbill/ldap"
)

func processRegexOnString(reg string, input string) string {
	re1, err := regexp.Compile(reg)
	if err != nil {
		logger(4, "Regex Error: "+err.Error(), false)
		return ""
	}
	//-- Get Array of all Matched max 100
	result := re1.FindAllString(input, 100)
	strReturn := ""
	//-- Loop Matches
	for _, match := range result {
		strReturn = match

		if strReturn != "" {
			return strReturn
		}
	}

	return strReturn
}
func getUserFieldValue(u *ldap.Entry, s string, custom map[string]string) string {
	//-- Dyniamicly Grab Mapped Value
	r := reflect.ValueOf(ldapImportConf.User.AccountMapping)
	f := reflect.Indirect(r).FieldByName(s)
	//-- Get Mapped Value
	var UserMapping = f.String()
	var stringToReturn = processComplexField(u, UserMapping)
	stringToReturn = processImportAction(custom, stringToReturn)
	return stringToReturn
}

// -- Get XMLMC Field from mapping via profile Object
func getProfileFieldValue(u *ldap.Entry, s string, custom map[string]string) string {
	//-- Dyniamicly Grab Mapped Value
	r := reflect.ValueOf(ldapImportConf.User.ProfileMapping)

	f := reflect.Indirect(r).FieldByName(s)

	//-- Get Mapped Value
	var UserProfileMapping = f.String()
	var stringToReturn = processComplexField(u, UserProfileMapping)
	stringToReturn = processImportAction(custom, stringToReturn)
	return stringToReturn
}

// -- Match any value wrapped in [] and get its LDAP Attribute Value
func processComplexField(u *ldap.Entry, s string) string {
	//-- Match $variables from String
	re1, err := regexp.Compile(`\[(.*?)\]`)
	if err != nil {
		logger(4, "Regex Error: "+err.Error(), false)
		return ""
	}
	//-- Get Array of all Matched max 100
	result := re1.FindAllString(s, 100)

	//-- Loop Matches
	for _, v := range result {
		//-- Grab LDAP Mapping value from result set
		var LDAPAttributeValue = u.GetAttributeValue(v[1 : len(v)-1])
		//-- Check for Invalid Value
		if LDAPAttributeValue == "" {
			//logger(3, "Unable to Load LDAP Attribute: "+v[1:len(v)-1]+" For Input Param: "+s, false)
			return LDAPAttributeValue
		}
		//-- TK UnescapeString to HTML entities are replaced
		s = html.UnescapeString(strings.Replace(s, v, LDAPAttributeValue, 1))

		//-- TK Remote Any White space leading and trailing a string
		s = strings.TrimSpace(s)
	}

	//-- Return Value
	return s
}

// -- Match Any value wrapped in {} and get its Import Action Value
func processImportAction(u map[string]string, s string) string {
	//-- Match $variables from String
	re1, err := regexp.Compile(`\{(.*?)\}`)
	if err != nil {
		logger(4, "Regex Error: "+err.Error(), false)
		return ""
	}
	//-- Get Array of all Matched max 100
	result := re1.FindAllString(s, 100)

	//-- Loop Matches
	for _, v := range result {
		//-- Grab LDAP Mapping value from result set
		var LDAPAttributeValue = u[v]
		//-- Check for Invalid Value
		if LDAPAttributeValue == "" {
			return LDAPAttributeValue
		}
		//-- TK UnescapeString to HTML entities are replaced
		s = html.UnescapeString(strings.Replace(s, v, LDAPAttributeValue, 1))

		//-- TK Remote Any White space leading and trailing a string
		s = strings.TrimSpace(s)

		if s != "" {
			//-- Return Value
			return s
		}

	}

	//-- Return Value
	return s
}

// -- Generate Password String
func generatePasswordString(importData *userWorkingDataStruct) string {
	pwdinst := hornbillpasswordgen.NewPasswordInstance()
	pwdinst.Length = passwordProfile.Length
	pwdinst.UseLower = true
	pwdinst.ForceLower = passwordProfile.ForceLower
	pwdinst.UseNumeric = true
	pwdinst.ForceNumeric = passwordProfile.ForceNumeric
	pwdinst.UseUpper = true
	pwdinst.ForceUpper = passwordProfile.ForceUpper
	pwdinst.UseSpecial = true
	pwdinst.ForceSpecial = passwordProfile.ForceSpecial
	pwdinst.Blacklist = passwordProfile.Blacklist
	if passwordProfile.CheckMustNotContain {
		pwdinst.MustNotContain = append(pwdinst.MustNotContain, importData.Account.FirstName)
		pwdinst.MustNotContain = append(pwdinst.MustNotContain, importData.Account.LastName)
		pwdinst.MustNotContain = append(pwdinst.MustNotContain, importData.Account.UserID)
	}

	//Generate a new password
	newPassword, _, err := pwdinst.GenPassword()

	if err != nil {
		logger(4, "Failed Password Auto Generation for: "+importData.Account.UserID+"  "+err.Error(), false)
		return ""
	}
	return newPassword
}

func loggerGen(t int, s string) string {
	//-- Ignore Logging level unless is 0
	if t < ldapImportConf.Advanced.LogLevel && t != 0 {
		return ""
	}

	var errorLogPrefix = ""
	//-- Create Log Entry
	switch t {
	case 1:
		errorLogPrefix = "[DEBUG] "
	case 2:
		errorLogPrefix = "[MESSAGE] "
	case 3:
		errorLogPrefix = "[WARN] "
	case 4:
		errorLogPrefix = "[ERROR] "
	}
	return errorLogPrefix + s + "\n\r"
}

func loggerWriteBuffer(s string) {
	if s != "" {
		logLines := strings.Split(s, "\n\r")
		for _, line := range logLines {
			if line != "" {
				logger(0, line, false)
			}
		}
	}
}
func deletefiles(path string, f os.FileInfo, err error) (e error) {
	var cutoff = (24 * time.Hour)
	cutoff = time.Duration(ldapImportConf.Advanced.LogRetention) * cutoff
	now := time.Now()
	// check each file if starts with prefix and our log name so other log files are not deleted and different imports can have differnt retentions
	if strings.HasPrefix(f.Name(), Flags.configLogPrefix+"LDAP_User_Import_") {

		if diff := now.Sub(f.ModTime()); diff > cutoff {
			logger(1, "Removing Old Log File: "+path, false)
			os.Remove(path)
		}

	}
	return

}

func runLogRetentionCheck() {
	logger(1, "Processing Old Log Files Current Retention Set to: "+fmt.Sprintf("%d", ldapImportConf.Advanced.LogRetention), true)

	if ldapImportConf.Advanced.LogRetention > 0 {
		//-- Curreny WD
		cwd, _ := os.Getwd()
		//-- Log Folder
		logPath := cwd + "/log"
		// walk through the files in the given path and perform partialrename()
		// function
		filepath.Walk(logPath, deletefiles)
	}

}

// -- Loggin function
func logger(t int, s string, outputtoCLI bool) {

	//-- Ignore Logging level unless is 0
	if t < ldapImportConf.Advanced.LogLevel && t != 0 {
		return
	}
	mutexLog.Lock()
	defer mutexLog.Unlock()

	onceLog.Do(func() {
		cwd, _ := os.Getwd()
		logPath := cwd + "/log"
		logFileName := logPath + "/" + Flags.configLogPrefix + "LDAP_User_Import_" + Time.timeNow + ".log"
		//-- If Folder Does Not Exist then create it
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			err := os.Mkdir(logPath, 0777)
			if err != nil {
				fmt.Printf("Error Creating Log Folder %q: %s \r", logPath, err)
				os.Exit(101)
			}
		}

		//-- Open Log File
		var err error
		f, err = os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0777)
		if err != nil {
			fmt.Printf("Error Creating Log File %q: %s \n", logFileName, err)
			os.Exit(100)
		}
		log.SetOutput(f)

	})

	red := color.New(color.FgRed).PrintfFunc()
	orange := color.New(color.FgCyan).PrintfFunc()
	var errorLogPrefix = ""
	//-- Create Log Entry
	switch t {
	case 0:
	case 1:
		errorLogPrefix = "[DEBUG] "
	case 2:
		errorLogPrefix = "[MESSAGE] "
	case 3:
		errorLogPrefix = "[WARN] "
	case 4:
		errorLogPrefix = "[ERROR] "
	}
	if outputtoCLI {
		if t == 3 {
			orange(errorLogPrefix + s + "\n")
		} else if t == 4 {
			red(errorLogPrefix + s + "\n")
		} else {
			fmt.Printf(errorLogPrefix + s + "\n")
		}

	}
	log.Println(errorLogPrefix + s)
}

func startImportHistory() bool {
	// We initilaise the connection pool the first time the function is called and reuse it
	// This is reuse the connections rather than creating a pool each invocation
	loggerAPI = apiLib.NewXmlmcInstance(Flags.configInstanceID)
	loggerAPI.SetAPIKey(Flags.configAPIKey)
	loggerAPI.SetTimeout(Flags.configAPITimeout)
	loggerAPI.SetJSONResponse(true)

	loggerAPI.SetParam("application", "com.hornbill.core")
	loggerAPI.SetParam("entity", "ImportsHistory")
	loggerAPI.SetParam("returnModifiedData", "true")
	loggerAPI.OpenElement("primaryEntityData")
	loggerAPI.OpenElement("record")
	loggerAPI.SetParam("h_import_id", Flags.configID)
	loggerAPI.SetParam("h_status", "1")
	loggerAPI.CloseElement("record")
	loggerAPI.CloseElement("primaryEntityData")

	RespBody, xmlmcErr := loggerAPI.Invoke("data", "entityAddRecord")
	var JSONResp xmlmcHistoryResponse
	if xmlmcErr != nil {
		logger(4, "Unable to write Import History: "+xmlmcErr.Error(), true)
		return false
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		logger(4, "Unable to write Import History: "+err.Error(), true)
		return false
	}
	if JSONResp.State.Error != "" {
		logger(4, "Unable to write Import History: "+JSONResp.State.Error, true)
		return false
	}

	//-- Store History ID for Later
	importHistoryID = JSONResp.Params.PrimaryEntityData.Record.HPkID

	return true
}
func completeImportHistory() bool {
	loggerAPI = apiLib.NewXmlmcInstance(Flags.configInstanceID)
	loggerAPI.SetAPIKey(Flags.configAPIKey)
	loggerAPI.SetTimeout(Flags.configAPITimeout)
	loggerAPI.SetJSONResponse(true)

	strMessage := ""

	strMessage += "=== XMLMC LDAP Import Utility V" + fmt.Sprintf("%v", version) + " ===\n\n"
	strMessage += "'''Errors''': " + fmt.Sprintf("%d", counters.errors) + "\n"

	strMessage += "'''Accounts Proccesed''': " + fmt.Sprintf("%d", len(HornbillCache.UsersWorking)) + "\n"
	strMessage += "'''Created''': " + fmt.Sprintf("%d", counters.created) + "\n"
	strMessage += "'''Updated''': " + fmt.Sprintf("%d", counters.updated) + "\n"
	strMessage += "'''Profiles Updated''': " + fmt.Sprintf("%d", counters.profileUpdated) + "\n"
	strMessage += "'''Images Updated''': " + fmt.Sprintf("%d", counters.imageUpdated) + "\n"
	strMessage += "'''Groups Updated''': " + fmt.Sprintf("%d", counters.groupUpdated) + "\n"
	strMessage += "'''Groups Removed''': " + fmt.Sprintf("%d", counters.groupsRemoved) + "\n"
	strMessage += "'''Roles Updated''': " + fmt.Sprintf("%d", counters.rolesUpdated) + "\n"

	loggerAPI.SetParam("application", "com.hornbill.core")
	loggerAPI.SetParam("entity", "ImportsHistory")
	loggerAPI.SetParam("returnModifiedData", "true")
	loggerAPI.OpenElement("primaryEntityData")
	loggerAPI.OpenElement("record")
	loggerAPI.SetParam("h_pk_id", importHistoryID)
	loggerAPI.SetParam("h_import_id", Flags.configID)
	if counters.errors > 0 {
		loggerAPI.SetParam("h_status", "3")
	} else {
		loggerAPI.SetParam("h_status", "2")
	}
	loggerAPI.SetParam("h_time_taken", strconv.FormatInt(int64(Time.endTime/time.Second), 10))
	loggerAPI.SetParam("h_message", strMessage)
	loggerAPI.CloseElement("record")
	loggerAPI.CloseElement("primaryEntityData")

	RespBody, xmlmcErr := loggerAPI.Invoke("data", "entityUpdateRecord")
	var JSONResp xmlmcHistoryResponse
	if xmlmcErr != nil {
		logger(4, "Unable to write Import History: "+xmlmcErr.Error(), true)
		return false
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		logger(4, "Unable to write Import History: "+err.Error(), true)
		return false
	}
	if JSONResp.State.Error != "" {
		logger(4, "Unable to write Import History: "+JSONResp.State.Error, true)
		return false
	}

	//-- Store History ID for Later
	importHistoryID = JSONResp.Params.PrimaryEntityData.Record.HPkID

	return true
}
func getLastHistory() {
	loggerAPI = apiLib.NewXmlmcInstance(Flags.configInstanceID)
	loggerAPI.SetAPIKey(Flags.configAPIKey)
	loggerAPI.SetTimeout(Flags.configAPITimeout)
	loggerAPI.SetJSONResponse(true)

	loggerAPI.SetParam("application", "com.hornbill.core")
	loggerAPI.SetParam("queryName", "getImportHistoryList")
	loggerAPI.SetParam("formatValues", "false")
	loggerAPI.SetParam("returnFoundRowCount", "false")
	loggerAPI.OpenElement("queryParams")
	loggerAPI.SetParam("import", Flags.configID)
	loggerAPI.SetParam("rowstart", "0")
	loggerAPI.SetParam("limit", "1")
	loggerAPI.SetParam("orderByWay", "descending")
	loggerAPI.SetParam("orderByField", "h_pk_id")
	loggerAPI.CloseElement("queryParams")

	RespBody, xmlmcErr := loggerAPI.Invoke("data", "queryExec")
	var JSONResp xmlmcHistoryItemResponse
	if xmlmcErr != nil {
		logger(4, "Unable to Query Import History: "+xmlmcErr.Error(), true)
		return
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		logger(4, "Unable to Query Import History: "+err.Error(), true)
		return
	}
	if JSONResp.State.Error != "" {
		logger(4, "Unable to Query Import History: "+JSONResp.State.Error, true)
		return
	}

	//-- Disable running multiple imports at once unless flagged as otherwise
	if len(JSONResp.Params.RowData.Row) > 0 {
		if JSONResp.Params.RowData.Row[0].HStatus == "1" && !Flags.configForceRun {
			logger(4, "Unable to run import, a provious import is still running", true)
			os.Exit(108)
		}
	}

}

// sysOptionGet - gets and returns sys setting value
func sysOptionGet(sysOption string) (optionValue string) {
	loggerAPI.SetParam("filter", sysOption)
	response, err := loggerAPI.Invoke("admin", "sysOptionGet")
	if err != nil {
		logger(4, "Could not retrieve System Setting ["+sysOption+"]: "+err.Error(), false)
		return
	}
	var jsonRespon xmlmcSettingResponse
	err = json.Unmarshal([]byte(response), &jsonRespon)
	if err != nil {
		logger(4, "Could not retrieve System Setting ["+sysOption+"]: "+err.Error(), false)
		return
	}
	if !jsonRespon.MethodResult {
		logger(4, "Could not retrieve System Setting ["+sysOption+"]: "+jsonRespon.State.Error, false)
		return
	}
	return jsonRespon.Params.Option[0].Value
}
