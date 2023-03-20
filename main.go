package main

//----- Packages -----
import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blang/semver"
	apiLib "github.com/hornbill/goApiLib"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

var (
	onceLog   sync.Once
	loggerAPI *apiLib.XmlmcInstStruct
	mutexLog  = &sync.Mutex{}
	f         *os.File
)

// Main
func main() {
	//-- Start Time for Durration
	Time.startTime = time.Now()
	//-- Start Time for Log File
	Time.timeNow = Time.startTime.Format("20060102150405")

	//-- Process Flags
	procFlags()

	//-- Used for Building
	if Flags.configVersion {
		fmt.Printf("%v \n", version)
		return
	}

	//Check version of utility, self-update if appropriate
	doSelfUpdate()

	//-- Load Configuration File Into Struct
	ldapImportConf = loadConfig()

	//-- Validation on Configuration File
	configError := validateConf()

	//-- Check for Error
	if configError != nil {
		logger(4, configError.Error(), true)
		logger(4, "Please Check your Configuration: "+Flags.configID, true)
		return
	}

	//-- Check import not already running
	getLastHistory()

	//Sort out maximum page size
	sysSettingPageSize, _ := strconv.Atoi(sysOptionGet("api.xmlmc.queryExec.maxResultsAllowed"))
	if ldapImportConf.Advanced.PageSize < sysSettingPageSize {
		ldapImportConf.Advanced.PageSize = sysSettingPageSize
		logger(0, "[MESSAGE] Overridden Page Size "+fmt.Sprintf("%d", ldapImportConf.Advanced.PageSize), true)
	}

	//-- Start Import
	logged := startImportHistory()

	//-- Check for Connections
	if !logged {
		logger(4, "Unable to Connect to Instance", true)
		return
	}

	//-- Clear Old Log Files
	runLogRetentionCheck()

	//-- Get Password Profile
	getPasswordProfile()

	ldapImportConf.User.HornbillUserIDColumn = strings.ToLower(ldapImportConf.User.HornbillUserIDColumn)

	//-- Query LDAP
	queryLdap()

	//-- Process LDAP User Data First
	//-- So we only store data about users we have
	processLDAPUsers()

	//-- Fetch Users from Hornbill
	loadUsers()

	//-- Load User Roles
	loadUsersRoles()

	//-- Fetch Sites
	loadSites()

	//-- Fetch Groups
	loadGroups()

	//-- Fetch User Groups
	loadUserGroups()

	//-- Create List of Actions that need to happen
	//-- (Create,Update,profileUpdate,Assign Role, Assign Group, Assign Site)
	processData()

	//-- Run Actions
	finaliseData()

	//-- End Ouput
	outputEnd()
}

// -- Process Input Flags
func procFlags() {
	//-- Grab Flags
	flag.StringVar(&Flags.configID, "config", "", "Id of Configuration To Load From Hornbill")
	flag.StringVar(&Flags.configLogPrefix, "logprefix", "", "Add prefix to the logfile")
	flag.BoolVar(&Flags.configDryRun, "dryrun", false, "Allow the Import to run without Creating or Updating users")
	flag.BoolVar(&Flags.configVersion, "version", false, "Output Version")
	flag.StringVar(&Flags.configInstanceID, "instanceid", "", "Id of the Hornbill Instance to connect to")
	flag.StringVar(&Flags.configAPIKey, "apikey", "", "API Key to use as Authentication when connecting to Hornbill Instance")
	flag.IntVar(&Flags.configAPITimeout, "apitimeout", 60, "Number of Seconds to Timeout an API Connection")
	flag.IntVar(&Flags.configWorkers, "workers", 1, "Number of Worker threads to use")
	flag.BoolVar(&Flags.configForceRun, "forcerun", false, "Bypass check on existing running import")
	flag.BoolVar(&Flags.configSkipCache, "sc", false, "Bypass caching of Hornbill users")

	//-- Parse Flags
	flag.Parse()

	//-- Output config
	if !Flags.configVersion {
		logger(2, "---- "+applicationName+" v"+fmt.Sprintf("%v", version)+" ----", true)
		logger(2, "Flag - config "+Flags.configID, true)
		logger(2, "Flag - logprefix "+Flags.configLogPrefix, true)
		logger(2, "Flag - dryrun "+fmt.Sprintf("%v", Flags.configDryRun), true)
		logger(2, "Flag - instanceid "+Flags.configInstanceID, true)
		logger(2, "Flag - apitimeout "+fmt.Sprintf("%v", Flags.configAPITimeout), true)
		logger(2, "Flag - workers "+fmt.Sprintf("%v", Flags.configWorkers)+"\n", true)
		logger(2, "Flag - forcerun "+fmt.Sprintf("%v", Flags.configForceRun), true)
	}
}

// -- Generate Output
func outputEnd() {
	logger(2, "Import Complete", true)
	//-- End output
	if counters.errors > 0 {
		logger(4, "One or more errors encountered please check the log file", true)
		logger(4, "Error Count: "+fmt.Sprintf("%d", counters.errors), true)
	}
	logger(2, "Accounts Processed: "+fmt.Sprintf("%d", len(HornbillCache.UsersWorking)), true)
	logger(2, "Created: "+fmt.Sprintf("%d", counters.created), true)
	logger(2, "Updated: "+fmt.Sprintf("%d", counters.updated), true)

	logger(2, "Status Updates: "+fmt.Sprintf("%d", counters.statusUpdated), true)

	logger(2, "Profiles Updated: "+fmt.Sprintf("%d", counters.profileUpdated), true)

	logger(2, "Images Updated: "+fmt.Sprintf("%d", counters.imageUpdated), true)
	logger(2, "Groups Added: "+fmt.Sprintf("%d", counters.groupUpdated), true)
	logger(2, "Groups Removed: "+fmt.Sprintf("%d", counters.groupsRemoved), true)
	logger(2, "Roles Added: "+fmt.Sprintf("%d", counters.rolesUpdated), true)

	//-- Show Time Takens
	Time.endTime = time.Since(Time.startTime).Round(time.Second)
	logger(2, "Time Taken: "+Time.endTime.String(), true)
	//-- complete
	mutexCounters.Lock()
	counters.traffic += loggerAPI.GetCount()
	counters.traffic += hornbillImport.GetCount()
	mutexCounters.Unlock()

	logger(2, "Total Traffic: "+fmt.Sprintf("%d", counters.traffic), true)

	completeImportHistory()
	logger(2, "---- XMLMC LDAP Import Complete ---- ", true)
}

// -- Function to Load Configruation File
func loadConfig() ldapImportConfStruct {

	if Flags.configInstanceID == "" {
		logger(4, "Config Error - No InstanceId Provided", true)
		os.Exit(103)
	}
	if Flags.configAPIKey == "" {
		logger(4, "Config Error - No ApiKey Provided", true)
		os.Exit(104)
	}
	if Flags.configID == "" {
		logger(4, "Config Error - No configID Provided", true)
		os.Exit(105)
	}
	logger(2, "Loading Configuration Data: "+Flags.configID, true)

	mc := apiLib.NewXmlmcInstance(Flags.configInstanceID)
	if mc.FileError != nil {
		if mc.FileError.Error() == "invalid character '<' looking for beginning of value" {
			logger(4, "106: Unable to read your instance information from Hornbill. Check the provided instanceid ["+Flags.configInstanceID+"] is correct (case sensitive).", true)
			os.Exit(106)
		} else {
			logger(4, "107: Unable to read your instance information from Hornbill. Check your connectivity to Hornbill and/or command line proxy access: "+mc.FileError.Error(), true)
			os.Exit(107)
		}
	}
	mc.SetAPIKey(Flags.configAPIKey)
	mc.SetTimeout(Flags.configAPITimeout)
	mc.SetJSONResponse(true)
	mc.SetParam("application", "com.hornbill.core")
	mc.SetParam("entity", "Imports")
	mc.SetParam("keyValue", Flags.configID)

	RespBody, xmlmcErr := mc.Invoke("data", "entityGetRecord")
	var JSONResp xmlmcConfigLoadResponse
	if xmlmcErr != nil {
		logger(4, "Error Loading Configuration: "+xmlmcErr.Error(), true)
		os.Exit(107)
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		logger(4, "Error Loading Configuration: "+err.Error(), true)
		os.Exit(107)
	}
	if JSONResp.State.Error != "" {
		logger(4, "Error Loading Configuration: "+JSONResp.State.Error, true)
		os.Exit(107)
	}

	//-- UnMarshal Config Definition
	var eldapConf ldapImportConfStruct

	err = json.Unmarshal([]byte(JSONResp.Params.PrimaryEntityData.Record.HDefinition), &eldapConf)
	if err != nil {
		logger(4, "Error Decoding Configuration: "+err.Error(), true)
		os.Exit(106)
	}

	if eldapConf.LDAP.Server.KeySafeID == 0 {
		logger(4, "Config Error - No LDAP Credentials Missing KeySafe Id", true)
		os.Exit(105)
	}
	//-- Load Authentication From KeySafe
	logger(2, "Loading LDAP Authentication Data: "+fmt.Sprintf("%d", eldapConf.LDAP.Server.KeySafeID), true)

	mc.SetParam("keyId", fmt.Sprintf("%d", eldapConf.LDAP.Server.KeySafeID))

	mc.SetParam("wantKeyData", "true")

	RespBody, xmlmcErr = mc.Invoke("admin", "keysafeGetKey")
	var JSONKeyResp xmlmcKeySafeResponse
	if xmlmcErr != nil {
		logger(4, "Error LDAP Authentication: "+xmlmcErr.Error(), true)
	}
	err = json.Unmarshal([]byte(RespBody), &JSONKeyResp)
	if err != nil {
		logger(4, "Error LDAP Authentication: "+err.Error(), true)
	}
	if JSONKeyResp.State.Error != "" {
		logger(4, "Error Loading LDAP Authentication: "+JSONKeyResp.State.Error, true)
	}
	err = json.Unmarshal([]byte(JSONKeyResp.Params.Data), &ldapServerAuth)
	if err != nil {
		logger(4, "Error Decoding LDAP Server Authentication: "+err.Error(), true)
	}

	logger(0, "[MESSAGE] Log Level "+fmt.Sprintf("%d", eldapConf.Advanced.LogLevel)+"", true)
	logger(0, "[MESSAGE] Import Defined Page Size "+fmt.Sprintf("%d", eldapConf.Advanced.PageSize), true)
	if eldapConf.User.Operation == "" {
		eldapConf.User.Operation = "Both"
	}
	//-- Return New Congfig
	return eldapConf
}

func validateConf() error {
	//-- Check LDAP Sever Connection type
	if ldapImportConf.LDAP.Server.ConnectionType != "" && ldapImportConf.LDAP.Server.ConnectionType != "SSL" && ldapImportConf.LDAP.Server.ConnectionType != "TLS" {
		err := errors.New("Invalid ConnectionType: '" + ldapImportConf.LDAP.Server.ConnectionType + "' Should be either '' or 'TLS' or 'SSL'")
		return err
	}
	return nil
}

// CounterInc Generic Counter Increment
func CounterInc(counter int) {
	mutexCounters.Lock()
	switch counter {
	case 1:
		counters.created++
	case 2:
		counters.updated++
	case 3:
		counters.profileUpdated++
	case 4:
		counters.imageUpdated++
	case 5:
		counters.groupUpdated++
	case 6:
		counters.rolesUpdated++
	case 7:
		counters.errors++
	case 8:
		counters.groupsRemoved++
	case 9:
		counters.statusUpdated++
	}
	mutexCounters.Unlock()
}

func doSelfUpdate() {
	v := semver.MustParse(version)
	latest, found, err := selfupdate.DetectLatest(repo)
	if err != nil {
		logger(5, "Error occurred while detecting version: "+err.Error(), true)
		return
	}
	if !found {
		logger(5, "Could not find Github repo: "+repo, true)
		return
	}

	latestMajorVersion := strings.Split(fmt.Sprintf("%v", latest.Version), ".")[0]
	latestMinorVersion := strings.Split(fmt.Sprintf("%v", latest.Version), ".")[1]
	latestPatchVersion := strings.Split(fmt.Sprintf("%v", latest.Version), ".")[2]

	currentMajorVersion := strings.Split(version, ".")[0]
	currentMinorVersion := strings.Split(version, ".")[1]
	currentPatchVersion := strings.Split(version, ".")[2]

	//Useful in dev, customers should never see current version > latest release version
	if currentMajorVersion > latestMajorVersion {
		logger(3, "Current version "+version+" (major) is greater than the latest release version on Github "+fmt.Sprintf("%v", latest.Version), true)
		return
	} else {
		if currentMinorVersion > latestMinorVersion {
			logger(3, "Current version "+version+" (minor) is greater than the latest release version on Github "+fmt.Sprintf("%v", latest.Version), true)
			return
		} else if currentPatchVersion > latestPatchVersion {
			logger(3, "Current version "+version+" (patch) is greater than the latest release version on Github "+fmt.Sprintf("%v", latest.Version), true)
			return
		}
	}
	if latestMajorVersion > currentMajorVersion {
		msg := "v" + version + " is not latest, you should upgrade to " + fmt.Sprintf("%v", latest.Version) + " by downloading the latest package from: https://github.com/" + repo + "/releases/latest"
		logger(5, msg, true)
		return
	}

	_, err = selfupdate.UpdateSelf(v, repo)
	if err != nil {
		logger(5, "Binary update failed: "+err.Error(), true)
		return
	}
	if latest.Version.Equals(v) {
		// latest version is the same as current version. It means current binary is up to date.
		logger(3, "Current binary is the latest version: "+version, true)
	} else {
		logger(3, "Successfully updated to version: "+fmt.Sprintf("%v", latest.Version), true)
		logger(3, "Release notes:\n"+latest.ReleaseNotes, true)
	}
}
