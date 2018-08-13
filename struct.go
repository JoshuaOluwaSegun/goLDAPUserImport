package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/hornbill/ldap"
)

//----- Constants -----
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const version = "3.1.2"

var mutexCounters = &sync.Mutex{}
var bufferMutex = &sync.Mutex{}
var importHistoryID string

// Flags List
var Flags struct {
	configID         string
	configLogPrefix  string
	configDryRun     bool
	configVersion    bool
	configInstanceID string
	configAPIKey     string
	configWorkers    int
	configAPITimeout int
	configForceRun   bool
}
var siteListStrut struct {
	ID   string
	Name string
}

// HornbillCache Struct
var HornbillCache struct {
	//-- User Id to account
	Users map[string]userAccountStruct
	//-- Site Name to Site Id Map
	Sites map[string]siteStruct
	//-- User Id to Map of Role IDs
	UserRoles map[string][]string
	//-- User Id to Map of Group Ids
	UserGroups map[string][]string
	//-- Group Name to Group Struct
	Groups map[string]userGroupStruct
	//-- GroupsId ID to Group Struct
	GroupsID map[string]userGroupStruct
	//-- User Working Data
	UsersWorking map[string]*userWorkingDataStruct
	//-- User Working Data Index Based for Workers
	UsersWorkingIndex map[int]*userWorkingDataStruct
	//-- Map Manager Name to Id
	Managers map[string]string
	//-- Map DN to UserId
	DN map[string]string
	//-- Image URI to image stuct
	Images map[string]imageStruct
}

// HornbillUserStatusMap Map
var HornbillUserStatusMap = map[string]string{
	"0": "active",
	"1": "suspended",
	"2": "archived",
}

type userImportJobs struct {
	create        bool
	update        bool
	updateProfile bool
	updateType    bool
	updateSite    bool
	updateImage   bool
	updateStatus  bool
}
type imageStruct struct {
	imageBytes    []byte
	imageCheckSum string
}
type userWorkingDataStruct struct {
	Account        AccountMappingStruct
	Profile        ProfileMappingStruct
	ImageURI       string
	LDAP           *ldap.Entry
	Custom         map[string]string
	Jobs           userImportJobs
	Roles          []string
	Groups         []userGroupStruct
	GroupsToRemove []string
}
type userGroupStruct struct {
	ID                     string
	Name                   string
	Type                   int
	Membership             string
	TasksView              bool
	TasksAction            bool
	OnlyOneGroupAssignment bool
}

// Time Struct
var Time struct {
	timeNow   string
	startTime time.Time
	endTime   time.Duration
}
var client = http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 1,
	},
	Timeout: time.Duration(10 * time.Second),
}

//----- Variables -----
var ldapImportConf ldapImportConfStruct
var ldapServerAuth ldapServerConfAuthStruct
var ldapUsers []*ldap.Entry
var counters struct {
	errors         uint16
	updated        uint16
	profileUpdated uint16
	imageUpdated   uint16
	groupUpdated   uint16
	groupsRemoved  uint16
	rolesUpdated   uint16

	statusUpdated uint16

	created uint16

	updatedSkipped uint16
	createskipped  uint16
	profileSkipped uint16

	traffic uint64
}

//----- Structures -----
type ldapServerConfAuthStruct struct {
	Host     string
	UserName string
	Password string
	Port     uint16
}
type ldapServerConfStruct struct {
	KeySafeID          int
	ConnectionType     string
	InsecureSkipVerify bool
	Scope              int
	DerefAliases       int
	SizeLimit          int
	TimeLimit          int
	TypesOnly          bool
	Filter             string
	DSN                string
	Debug              bool
}

type ldapImportConfStruct struct {
	APIKey     string `json:"APIKey"`
	InstanceID string `json:"InstanceId"`
	LDAP       struct {
		Server ldapServerConfStruct `json:"Server"`
		Query  struct {
			Attributes   []string `json:"Attributes"`
			Scope        int      `json:"Scope"`
			DerefAliases int      `json:"DerefAliases"`
			SizeLimit    int      `json:"SizeLimit"`
			TimeLimit    int      `json:"TimeLimit"`
			TypesOnly    bool     `json:"TypesOnly"`
			Filter       string   `json:"Filter"`
			DSN          string   `json:"DSN"`
		} `json:"Query"`
	} `json:"LDAP"`
	User struct {
		AccountMapping AccountMappingStruct `json:"AccountMapping"`
		UserDN         string               `json:"UserDN"`
		Type           struct {
			Action string `json:"Action"`
		} `json:"Type"`
		Status struct {
			Action string `json:"Action"`
			Value  string `json:"Value"`
		} `json:"Status"`
		Role struct {
			Action string   `json:"Action"`
			Roles  []string `json:"Roles"`
		} `json:"Role"`
		ProfileMapping ProfileMappingStruct `json:"ProfileMapping"`
		Manager        struct {
			Action  string `json:"Action"`
			Value   string `json:"Value"`
			Options struct {
				GetStringFromValue struct {
					Regex   string `json:"Regex"`
					Reverse bool   `json:"Reverse"`
				} `json:"GetStringFromValue"`
				MatchAgainstDistinguishedName bool `json:"MatchAgainstDistinguishedName"`
				Search                        struct {
					Enable      bool   `json:"Enable"`
					SearchField string `json:"SearchField"`
				} `json:"Search"`
			} `json:"Options"`
		} `json:"Manager"`
		Image struct {
			Action             string `json:"Action"`
			UploadType         string `json:"UploadType"`
			InsecureSkipVerify bool   `json:"InsecureSkipVerify"`
			ImageType          string `json:"ImageType"`
			URI                string `json:"URI"`
		} `json:"Image"`
		Site struct {
			Action string `json:"Action"`
			Value  string `json:"Value"`
		} `json:"Site"`
		Org []struct {
			Action   string `json:"Action"`
			Value    string `json:"Value"`
			MemberOf string `json:"MemberOf"`
			Options  struct {
				Type                   int    `json:"Type"`
				Membership             string `json:"Membership"`
				TasksView              bool   `json:"TasksView"`
				TasksAction            bool   `json:"TasksAction"`
				OnlyOneGroupAssignment bool   `json:"OnlyOneGroupAssignment"`
			} `json:"Options"`
		} `json:"Org"`
	} `json:"User"`
	Advanced struct {
		LogLevel     int `json:"LogLevel"`
		LogRetention int `json:"LogRetention"`
		PageSize     int `json:"PageSize"`
	} `json:"Advanced"`
	Actions []struct {
		Action  string `json:"Action"`
		Value   string `json:"Value"`
		Output  string `json:"Output"`
		Options struct {
			RegexValue  string `json:"regexValue"`
			ReplaceFrom string `json:"replaceFrom"`
			ReplaceWith string `json:"replaceWith"`
		} `json:"Options"`
	} `json:"Actions"`
}

// AccountMappingStruct Used
type AccountMappingStruct struct {
	UserID         string `json:"UserID"`
	UserType       string `json:"UserType"`
	Name           string `json:"Name"`
	Password       string `json:"Password"`
	FirstName      string `json:"FirstName"`
	LastName       string `json:"LastName"`
	JobTitle       string `json:"JobTitle"`
	Site           string `json:"Site"`
	Phone          string `json:"Phone"`
	Email          string `json:"Email"`
	Mobile         string `json:"Mobile"`
	AbsenceMessage string `json:"AbsenceMessage"`
	TimeZone       string `json:"TimeZone"`
	Language       string `json:"Language"`
	DateTimeFormat string `json:"DateTimeFormat"`
	DateFormat     string `json:"DateFormat"`
	TimeFormat     string `json:"TimeFormat"`
	CurrencySymbol string `json:"CurrencySymbol"`
	CountryCode    string `json:"CountryCode"`
}

// ProfileMappingStruct Used
type ProfileMappingStruct struct {
	MiddleName        string `json:"middleName"`
	JobDescription    string `json:"jobDescription"`
	Manager           string `json:"manager"`
	WorkPhone         string `json:"workPhone"`
	Qualifications    string `json:"qualifications"`
	Interests         string `json:"interests"`
	Expertise         string `json:"expertise"`
	Gender            string `json:"gender"`
	Dob               string `json:"dob"`
	Nationality       string `json:"nationality"`
	Religion          string `json:"religion"`
	HomeTelephone     string `json:"homeTelephone"`
	SocialNetworkA    string `json:"socialNetworkA"`
	SocialNetworkB    string `json:"socialNetworkB"`
	SocialNetworkC    string `json:"socialNetworkC"`
	SocialNetworkD    string `json:"socialNetworkD"`
	SocialNetworkE    string `json:"socialNetworkE"`
	SocialNetworkF    string `json:"socialNetworkF"`
	SocialNetworkG    string `json:"socialNetworkG"`
	SocialNetworkH    string `json:"socialNetworkH"`
	PersonalInterests string `json:"personalInterests"`
	HomeAddress       string `json:"homeAddress"`
	PersonalBlog      string `json:"personalBlog"`
	Attrib1           string `json:"Attrib1"`
	Attrib2           string `json:"Attrib2"`
	Attrib3           string `json:"Attrib3"`
	Attrib4           string `json:"Attrib4"`
	Attrib5           string `json:"Attrib5"`
	Attrib6           string `json:"Attrib6"`
	Attrib7           string `json:"Attrib7"`
	Attrib8           string `json:"Attrib8"`
}

type xmlmcSiteListResponse struct {
	Params struct {
		RowsAffected int `json:"rowsAffected"`
		LastInsertID int `json:"lastInsertId"`
		RowData      struct {
			Row []siteStruct `json:"row"`
		} `json:"rowData"`
		QueryExecTime    int `json:"queryExecTime"`
		QueryResultsTime int `json:"queryResultsTime"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcUserListResponse struct {
	Params struct {
		RowData struct {
			Row []userAccountStruct `json:"row"`
		} `json:"rowData"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type siteStruct struct {
	HID       string `json:"h_id"`
	HSiteName string `json:"h_site_name"`
}
type roleStruct struct {
	HUserID string `json:"h_user_id"`
	HRole   string `json:"h_role"`
}
type groupStruct struct {
	HID   string `json:"h_id"`
	HName string `json:"h_name"`
	HType string `json:"h_type"`
}
type userAccountStruct struct {
	HUserID              string `json:"h_user_id"`
	HName                string `json:"h_name"`
	HFirstName           string `json:"h_first_name"`
	HMiddleName          string `json:"h_middle_name"`
	HLastName            string `json:"h_last_name"`
	HPhone               string `json:"h_phone"`
	HEmail               string `json:"h_email"`
	HMobile              string `json:"h_mobile"`
	HJobTitle            string `json:"h_job_title"`
	HLoginCreds          string `json:"h_login_creds"`
	HClass               string `json:"h_class"`
	HAvailStatus         string `json:"h_avail_status"`
	HAvailStatusMsg      string `json:"h_avail_status_msg"`
	HTimezone            string `json:"h_timezone"`
	HCountry             string `json:"h_country"`
	HLanguage            string `json:"h_language"`
	HDateTimeFormat      string `json:"h_date_time_format"`
	HDateFormat          string `json:"h_date_format"`
	HTimeFormat          string `json:"h_time_format"`
	HCurrencySymbol      string `json:"h_currency_symbol"`
	HLastLogon           string `json:"h_last_logon"`
	HSnA                 string `json:"h_sn_a"`
	HSnB                 string `json:"h_sn_b"`
	HSnC                 string `json:"h_sn_c"`
	HSnD                 string `json:"h_sn_d"`
	HSnE                 string `json:"h_sn_e"`
	HSnF                 string `json:"h_sn_f"`
	HSnG                 string `json:"h_sn_g"`
	HSnH                 string `json:"h_sn_h"`
	HIconRef             string `json:"h_icon_ref"`
	HIconChecksum        string `json:"h_icon_checksum"`
	HDob                 string `json:"h_dob"`
	HAccountStatus       string `json:"h_account_status"`
	HFailedAttempts      string `json:"h_failed_attempts"`
	HIdxRef              string `json:"h_idx_ref"`
	HSite                string `json:"h_site"`
	HManager             string `json:"h_manager"`
	HSummary             string `json:"h_summary"`
	HInterests           string `json:"h_interests"`
	HQualifications      string `json:"h_qualifications"`
	HPersonalInterests   string `json:"h_personal_interests"`
	HSkills              string `json:"h_skills"`
	HGender              string `json:"h_gender"`
	HNationality         string `json:"h_nationality"`
	HReligion            string `json:"h_religion"`
	HHomeTelephoneNumber string `json:"h_home_telephone_number"`
	HHomeAddress         string `json:"h_home_address"`
	HBlog                string `json:"h_blog"`
	HAttrib1             string `json:"h_attrib_1"`
	HAttrib2             string `json:"h_attrib_2"`
	HAttrib3             string `json:"h_attrib_3"`
	HAttrib4             string `json:"h_attrib_4"`
	HAttrib5             string `json:"h_attrib_5"`
	HAttrib6             string `json:"h_attrib_6"`
	HAttrib7             string `json:"h_attrib_7"`
	HAttrib8             string `json:"h_attrib_8"`
}
type xmlmcUserRolesListResponse struct {
	Params struct {
		RowsAffected int `json:"rowsAffected"`
		LastInsertID int `json:"lastInsertId"`
		RowData      struct {
			Row []roleStruct `json:"row"`
		} `json:"rowData"`
		QueryExecTime    int `json:"queryExecTime"`
		QueryResultsTime int `json:"queryResultsTime"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcUserGroupListResponse struct {
	Params struct {
		RowsAffected int `json:"rowsAffected"`
		LastInsertID int `json:"lastInsertId"`
		RowData      struct {
			Row []struct {
				HUserID  string `json:"h_user_id"`
				HGroupID string `json:"h_group_id"`
			} `json:"row"`
		} `json:"rowData"`
		QueryExecTime    int `json:"queryExecTime"`
		QueryResultsTime int `json:"queryResultsTime"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}

type xmlmcGroupListResponse struct {
	Params struct {
		RowsAffected int `json:"rowsAffected"`
		LastInsertID int `json:"lastInsertId"`
		RowData      struct {
			Row []groupStruct `json:"row"`
		} `json:"rowData"`
		QueryExecTime    int `json:"queryExecTime"`
		QueryResultsTime int `json:"queryResultsTime"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcConfigLoadResponse struct {
	Params struct {
		PrimaryEntityData struct {
			Entity string `json:"entity"`
			Record struct {
				HPkID         string `json:"h_pk_id"`
				HName         string `json:"h_name"`
				HType         string `json:"h_type"`
				HDescription  string `json:"h_description"`
				HCreatedOn    string `json:"h_created_on"`
				HCreatedBy    string `json:"h_created_by"`
				HUpdatedBy    string `json:"h_updated_by"`
				HLastupdateOn string `json:"h_lastupdate_on"`
				HDefinition   string `json:"h_definition"`
			} `json:"record"`
		} `json:"primaryEntityData"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcKeySafeResponse struct {
	Status bool `json:"@status"`
	Params struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Schema string `json:"schema"`
		Data   string `json:"data"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcCountResponse struct {
	Params struct {
		RowData struct {
			Row []struct {
				Count string `json:"count"`
			} `json:"row"`
		} `json:"rowData"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcHistoryItemResponse struct {
	Params struct {
		RowsAffected int `json:"rowsAffected"`
		LastInsertID int `json:"lastInsertId"`
		RowData      struct {
			Row []struct {
				HPkID         string `json:"h_pk_id"`
				HImportID     string `json:"h_import_id"`
				HStatus       string `json:"h_status"`
				HTimeTaken    string `json:"h_time_taken"`
				HCreatedOn    string `json:"h_created_on"`
				HCreatedBy    string `json:"h_created_by"`
				HLastupdateOn string `json:"h_lastupdate_on"`
				HMessage      string `json:"h_message"`
			} `json:"row"`
		} `json:"rowData"`
		FoundRows        string `json:"foundRows"`
		QueryExecTime    int    `json:"queryExecTime"`
		QueryResultsTime int    `json:"queryResultsTime"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type xmlmcHistoryResponse struct {
	Params struct {
		PrimaryEntityData struct {
			Record struct {
				HPkID      string `json:"h_pk_id"`
				HImportID  string `json:"h_import_id"`
				HStatus    string `json:"h_status"`
				HCreatedOn string `json:"h_created_on"`
				HCreatedBy string `json:"h_created_by"`
			} `json:"record"`
		} `json:"primaryEntityData"`
	} `json:"params"`
	State stateJSONStruct `json:"state"`
}
type stateJSONStruct struct {
	Code      string `json:"code"`
	Service   string `json:"service"`
	Operation string `json:"operation"`
	Error     string `json:"error"`
}
type xmlmcLogMessageResponse struct {
	MethodResult string      `xml:"status,attr"`
	State        stateStruct `xml:"state"`
}
type stateStruct struct {
	Code     string `xml:"code"`
	ErrorRet string `xml:"error"`
}
type xmlmcResponse struct {
	MethodResult string          `json:"status,attr"`
	State        stateJSONStruct `json:"state"`
}
