package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	apiLib "github.com/hornbill/goApiLib"
)

// Write DN and User ID to Cache
func writeUserToCache(DN string, ID string) {
	_, found := HornbillCache.DN[DN]
	if !found {
		HornbillCache.DN[DN] = ID
	}
}

// Get User ID From Cache By DN
func getUserFromDNCache(DN string) string {
	_, found := HornbillCache.DN[DN]
	if found {
		return HornbillCache.DN[DN]
	}
	return ""
}

func userCreate(hIF *apiLib.XmlmcInstStruct, user *userWorkingDataStruct, buffer *bytes.Buffer) (bool, error) {
	buffer.WriteString(loggerGen(1, "User Create: "+user.Account.UserID+" ("+user.Account.CheckID+")"))
	//-- Set Params based on already processed params
	hIF.SetParam("userId", user.Jobs.id)
	if user.Account.LoginID != "" {
		hIF.SetParam("loginId", user.Account.LoginID)
	}
	if user.Account.EmployeeID != "" {
		hIF.SetParam("employeeId", user.Account.EmployeeID)
	}
	hIF.SetParam("name", user.Account.Name)
	//-- Password is base64 encoded already in process_data
	hIF.SetParam("password", user.Account.Password)
	hIF.SetParam("userType", user.Account.UserType)
	if user.Account.Enable2FA != "" {
		hIF.SetParam("enable2fa", user.Account.Enable2FA)
	}
	if user.Account.FirstName != "" {
		hIF.SetParam("firstName", user.Account.FirstName)
	}
	if user.Account.LastName != "" {
		hIF.SetParam("lastName", user.Account.LastName)
	}
	if user.Account.JobTitle != "" {
		hIF.SetParam("jobTitle", user.Account.JobTitle)
	}
	if user.Account.Site != "" {
		hIF.SetParam("site", user.Account.Site)
	}
	if user.Account.Phone != "" {
		hIF.SetParam("phone", user.Account.Phone)
	}
	if user.Account.Email != "" {
		hIF.SetParam("email", user.Account.Email)
	}
	if user.Account.Mobile != "" {
		hIF.SetParam("mobile", user.Account.Mobile)
	}
	//hIF.SetParam("availabilityStatus", 1)
	if user.Account.AbsenceMessage != "" {
		hIF.SetParam("absenceMessage", user.Account.AbsenceMessage)
	}
	if user.Account.TimeZone != "" {
		hIF.SetParam("timeZone", user.Account.TimeZone)
	}
	if user.Account.Language != "" {
		hIF.SetParam("language", user.Account.Language)
	}
	if user.Account.DateTimeFormat != "" {
		hIF.SetParam("dateTimeFormat", user.Account.DateTimeFormat)
	}
	if user.Account.DateFormat != "" {
		hIF.SetParam("dateFormat", user.Account.DateFormat)
	}
	if user.Account.TimeFormat != "" {
		hIF.SetParam("timeFormat", user.Account.TimeFormat)
	}
	if user.Account.CurrencySymbol != "" {
		hIF.SetParam("currencySymbol", user.Account.CurrencySymbol)
	}
	if user.Account.CountryCode != "" {
		hIF.SetParam("countryCode", user.Account.CountryCode)
	}
	if user.Account.DisableDirectLogin != "" ||
		user.Account.DisableDirectLoginPasswordReset != "" ||
		user.Account.DisableDevicePairing != "" {
		hIF.OpenElement("securityOptions")
		if user.Account.DisableDirectLogin != "" {
			hIF.SetParam("disableDirectLogin", user.Account.DisableDirectLogin)
		}
		if user.Account.DisableDirectLoginPasswordReset != "" {
			hIF.SetParam("disableDirectLoginPasswordReset", user.Account.DisableDirectLoginPasswordReset)
		}
		if user.Account.DisableDevicePairing != "" {
			hIF.SetParam("disableDevicePairing", user.Account.DisableDevicePairing)
		}
		hIF.CloseElement("securityOptions")
	}

	//hIF.SetParam("notifyEmail", "")
	//hIF.SetParam("notifyTextMessage", "")

	//-- Dry Run
	if Flags.configDryRun {
		var XMLSTRING = hIF.GetParam()

		buffer.WriteString(loggerGen(1, "User Create XML "+XMLSTRING))
		hIF.ClearParam()
		return true, nil
	}

	RespBody, xmlmcErr := hIF.Invoke("admin", "userCreate")
	var JSONResp xmlmcResponse
	if xmlmcErr != nil {
		return false, xmlmcErr
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		return false, err
	}
	if JSONResp.State.Error != "" {
		return false, errors.New(JSONResp.State.Error)
	}
	buffer.WriteString(loggerGen(1, "User Create Success: "+user.Jobs.id))
	return true, nil
}

func checkUserFieldClear(value string) string {
	if strings.EqualFold(value, "__clear__") {
		return ""
	}
	return value
}
func userUpdate(hIF *apiLib.XmlmcInstStruct, user *userWorkingDataStruct, buffer *bytes.Buffer) (bool, error) {

	buffer.WriteString(loggerGen(1, "User Update: "+user.Account.CheckID+" ("+user.Jobs.id+")"))
	//-- Set Params based on already processed params
	hIF.SetParam("userId", user.Jobs.id)

	if user.Account.LoginID != "" && user.Account.LoginID != "hornbillLoginIDDeDup" {
		hIF.SetParam("loginId", checkUserFieldClear(user.Account.LoginID))
	}

	if user.Account.EmployeeID != "" {
		hIF.SetParam("employeeId", checkUserFieldClear(user.Account.EmployeeID))
	}

	hIF.SetParam("userType", user.Account.UserType)
	if user.Account.Enable2FA != "" {
		hIF.SetParam("enable2fa", user.Account.Enable2FA)
	}
	if user.Account.Name != "" {
		hIF.SetParam("name", checkUserFieldClear(user.Account.Name))
	}

	if user.Account.FirstName != "" {
		hIF.SetParam("firstName", checkUserFieldClear(user.Account.FirstName))
	}
	if user.Account.LastName != "" {
		hIF.SetParam("lastName", checkUserFieldClear(user.Account.LastName))
	}
	if user.Account.JobTitle != "" {
		hIF.SetParam("jobTitle", checkUserFieldClear(user.Account.JobTitle))
	}
	if user.Account.Site != "" {
		siteVal := checkUserFieldClear(user.Account.Site)
		if siteVal == "" {
			siteVal = "0"
		}
		hIF.SetParam("site", siteVal)
	}
	if user.Account.Phone != "" {
		hIF.SetParam("phone", checkUserFieldClear(user.Account.Phone))
	}
	if user.Account.Email != "" {
		hIF.SetParam("email", checkUserFieldClear(user.Account.Email))
	}
	if user.Account.Mobile != "" {
		hIF.SetParam("mobile", checkUserFieldClear(user.Account.Mobile))
	}
	if user.Account.AbsenceMessage != "" {
		hIF.SetParam("absenceMessage", checkUserFieldClear(user.Account.AbsenceMessage))
	}
	if user.Account.TimeZone != "" {
		hIF.SetParam("timeZone", checkUserFieldClear(user.Account.TimeZone))
	}
	if user.Account.Language != "" {
		hIF.SetParam("language", checkUserFieldClear(user.Account.Language))
	}
	if user.Account.DateTimeFormat != "" {
		hIF.SetParam("dateTimeFormat", checkUserFieldClear(user.Account.DateTimeFormat))
	}
	if user.Account.DateFormat != "" {
		hIF.SetParam("dateFormat", checkUserFieldClear(user.Account.DateFormat))
	}
	if user.Account.TimeFormat != "" {
		hIF.SetParam("timeFormat", checkUserFieldClear(user.Account.TimeFormat))
	}
	if user.Account.CurrencySymbol != "" {
		hIF.SetParam("currencySymbol", checkUserFieldClear(user.Account.CurrencySymbol))
	}
	if user.Account.CountryCode != "" {
		hIF.SetParam("countryCode", checkUserFieldClear(user.Account.CountryCode))
	}
	if user.Account.UpdateSecOptions {
		hIF.OpenElement("securityOptions")
		hIF.SetParam("disableDirectLogin", user.Account.DisableDirectLogin)
		hIF.SetParam("disableDirectLoginPasswordReset", user.Account.DisableDirectLoginPasswordReset)
		hIF.SetParam("disableDevicePairing", user.Account.DisableDevicePairing)
		hIF.CloseElement("securityOptions")
	}

	var XMLSTRING = hIF.GetParam()
	//-- Dry Run
	if Flags.configDryRun {
		buffer.WriteString(loggerGen(1, "User Update XML "+XMLSTRING))
		hIF.ClearParam()
		return true, nil
	}

	RespBody, xmlmcErr := hIF.Invoke("admin", "userUpdate")
	var JSONResp xmlmcResponse
	if xmlmcErr != nil {
		buffer.WriteString(loggerGen(1, "User Update XML "+XMLSTRING))
		return false, xmlmcErr
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		buffer.WriteString(loggerGen(1, "User Update XML "+XMLSTRING))
		return false, err
	}
	if JSONResp.State.Error != "" {
		buffer.WriteString(loggerGen(1, "User Update XML "+XMLSTRING))
		return false, errors.New(JSONResp.State.Error)
	}
	buffer.WriteString(loggerGen(1, "User Update Success: "+user.Jobs.id))
	return true, nil
}

func userProfileUpdate(hIF *apiLib.XmlmcInstStruct, user *userWorkingDataStruct, buffer *bytes.Buffer) (bool, error) {
	buffer.WriteString(loggerGen(1, "User Update Profile: "+user.Jobs.id))

	hIF.OpenElement("profileData")

	//-- Set Params based on already processed params
	hIF.SetParam("userId", user.Jobs.id)

	if user.Profile.MiddleName != "" {
		hIF.SetParam("middleName", checkUserFieldClear(user.Profile.MiddleName))
	}
	if user.Profile.JobDescription != "" {
		hIF.SetParam("jobDescription", checkUserFieldClear(user.Profile.JobDescription))
	}
	if user.Profile.Manager != "" {
		hIF.SetParam("manager", checkUserFieldClear(user.Profile.Manager))
	}
	//	if user.Profile.WorkPhone != "" {
	//		hIF.SetParam("workPhone", checkUserFieldClear(user.Profile.WorkPhone))
	//	}
	if user.Profile.Qualifications != "" {
		hIF.SetParam("qualifications", checkUserFieldClear(user.Profile.Qualifications))
	}
	if user.Profile.Interests != "" {
		hIF.SetParam("interests", checkUserFieldClear(user.Profile.Interests))
	}
	if user.Profile.Expertise != "" {
		hIF.SetParam("expertise", checkUserFieldClear(user.Profile.Expertise))
	}
	if user.Profile.Gender != "" {
		hIF.SetParam("gender", checkUserFieldClear(user.Profile.Gender))
	}
	if user.Profile.Dob != "" {
		hIF.SetParam("dob", checkUserFieldClear(user.Profile.Dob))
	}
	if user.Profile.Nationality != "" {
		hIF.SetParam("nationality", checkUserFieldClear(user.Profile.Nationality))
	}
	if user.Profile.Religion != "" {
		hIF.SetParam("religion", checkUserFieldClear(user.Profile.Religion))
	}
	if user.Profile.HomeTelephone != "" {
		hIF.SetParam("homeTelephone", checkUserFieldClear(user.Profile.HomeTelephone))
	}
	if user.Profile.SocialNetworkA != "" {
		hIF.SetParam("socialNetworkA", checkUserFieldClear(user.Profile.SocialNetworkA))
	}
	if user.Profile.SocialNetworkB != "" {
		hIF.SetParam("socialNetworkB", checkUserFieldClear(user.Profile.SocialNetworkB))
	}
	if user.Profile.SocialNetworkC != "" {
		hIF.SetParam("socialNetworkC", checkUserFieldClear(user.Profile.SocialNetworkC))
	}
	if user.Profile.SocialNetworkD != "" {
		hIF.SetParam("socialNetworkD", checkUserFieldClear(user.Profile.SocialNetworkD))
	}
	if user.Profile.SocialNetworkE != "" {
		hIF.SetParam("socialNetworkE", checkUserFieldClear(user.Profile.SocialNetworkE))
	}
	if user.Profile.SocialNetworkF != "" {
		hIF.SetParam("socialNetworkF", checkUserFieldClear(user.Profile.SocialNetworkF))
	}
	if user.Profile.SocialNetworkG != "" {
		hIF.SetParam("socialNetworkG", checkUserFieldClear(user.Profile.SocialNetworkG))
	}
	if user.Profile.SocialNetworkH != "" {
		hIF.SetParam("socialNetworkH", checkUserFieldClear(user.Profile.SocialNetworkH))
	}
	if user.Profile.PersonalInterests != "" {
		hIF.SetParam("personalInterests", checkUserFieldClear(user.Profile.PersonalInterests))
	}
	if user.Profile.HomeAddress != "" {
		hIF.SetParam("homeAddress", checkUserFieldClear(user.Profile.HomeAddress))
	}
	if user.Profile.PersonalBlog != "" {
		hIF.SetParam("personalBlog", checkUserFieldClear(user.Profile.PersonalBlog))
	}
	if user.Profile.Attrib1 != "" {
		hIF.SetParam("attrib1", checkUserFieldClear(user.Profile.Attrib1))
	}
	if user.Profile.Attrib2 != "" {
		hIF.SetParam("attrib2", checkUserFieldClear(user.Profile.Attrib2))
	}
	if user.Profile.Attrib3 != "" {
		hIF.SetParam("attrib3", checkUserFieldClear(user.Profile.Attrib3))
	}
	if user.Profile.Attrib4 != "" {
		hIF.SetParam("attrib4", checkUserFieldClear(user.Profile.Attrib4))
	}
	if user.Profile.Attrib5 != "" {
		hIF.SetParam("attrib5", checkUserFieldClear(user.Profile.Attrib5))
	}
	if user.Profile.Attrib6 != "" {
		hIF.SetParam("attrib6", checkUserFieldClear(user.Profile.Attrib6))
	}
	if user.Profile.Attrib7 != "" {
		hIF.SetParam("attrib7", checkUserFieldClear(user.Profile.Attrib7))
	}
	if user.Profile.Attrib8 != "" {
		hIF.SetParam("attrib8", checkUserFieldClear(user.Profile.Attrib8))
	}

	hIF.CloseElement("profileData")
	var XMLSTRING = hIF.GetParam()
	//-- Dry Run
	if Flags.configDryRun {
		buffer.WriteString(loggerGen(1, "User Update Profile XML "+XMLSTRING))
		hIF.ClearParam()
		return true, nil
	}

	RespBody, xmlmcErr := hIF.Invoke("admin", "userProfileSet")
	var JSONResp xmlmcResponse
	if xmlmcErr != nil {
		buffer.WriteString(loggerGen(1, "User Update Profile XML "+XMLSTRING))
		return false, xmlmcErr
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		buffer.WriteString(loggerGen(1, "User Update Profile XML "+XMLSTRING))
		return false, err
	}
	if JSONResp.State.Error != "" {
		buffer.WriteString(loggerGen(1, "User Update Profile XML "+XMLSTRING))
		return false, errors.New(JSONResp.State.Error)
	}

	buffer.WriteString(loggerGen(1, "User Update Profile Success: "+user.Account.CheckID+" ("+user.Jobs.id+")"))
	return true, nil
}

func userRolesUpdate(hIF *apiLib.XmlmcInstStruct, user *userWorkingDataStruct, buffer *bytes.Buffer) (bool, error) {

	hIF.SetParam("userId", user.Jobs.id)
	for roleIndex := range user.Roles {
		role := user.Roles[roleIndex]
		buffer.WriteString(loggerGen(1, "User Add Role User: "+user.Account.CheckID+" ("+user.Jobs.id+")"+" Role: "+role))
		hIF.SetParam("role", role)
	}
	var XMLSTRING = hIF.GetParam()
	if Flags.configDryRun {
		buffer.WriteString(loggerGen(1, "User Add Role XML "+XMLSTRING))
		hIF.ClearParam()
		return true, nil
	}

	RespBody, xmlmcErr := hIF.Invoke("admin", "userAddRole")
	var JSONResp xmlmcResponse
	if xmlmcErr != nil {
		buffer.WriteString(loggerGen(1, "User Add Role XML "+XMLSTRING))
		return false, xmlmcErr
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		buffer.WriteString(loggerGen(1, "User Add Role XML "+XMLSTRING))
		return false, err
	}
	if JSONResp.State.Error != "" {
		buffer.WriteString(loggerGen(1, "User Add Role XML "+XMLSTRING))
		return false, errors.New(JSONResp.State.Error)
	}
	buffer.WriteString(loggerGen(1, "Role added to User: "+user.Account.CheckID+" ("+user.Jobs.id+")"))
	return true, nil
}

func userStatusUpdate(hIF *apiLib.XmlmcInstStruct, user *userWorkingDataStruct, buffer *bytes.Buffer) (bool, error) {

	hIF.SetParam("userId", user.Jobs.id)
	hIF.SetParam("accountStatus", ldapImportConf.User.Status.Value)

	var XMLSTRING = hIF.GetParam()
	if Flags.configDryRun {
		buffer.WriteString(loggerGen(1, "User Set Status XML "+XMLSTRING))
		hIF.ClearParam()
		return true, nil
	}

	RespBody, xmlmcErr := hIF.Invoke("admin", "userSetAccountStatus")
	var JSONResp xmlmcResponse
	if xmlmcErr != nil {
		buffer.WriteString(loggerGen(1, "User Set Status XML "+XMLSTRING))
		return false, xmlmcErr
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		buffer.WriteString(loggerGen(1, "User Set Status XML "+XMLSTRING))
		return false, err
	}
	if JSONResp.State.Error != "" {
		buffer.WriteString(loggerGen(1, "User Set Status XML "+XMLSTRING))
		return false, errors.New(JSONResp.State.Error)
	}
	buffer.WriteString(loggerGen(1, "User Status Updated: "+user.Account.CheckID+" ("+user.Jobs.id+")"))
	return true, nil
}
