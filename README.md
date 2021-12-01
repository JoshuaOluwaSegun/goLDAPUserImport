### LDAP Import Go - [GO](https://golang.org/) Import Script to Hornbill

### Quick links
- [Installation](#installation)
- [Config](#config)
- [Execute](#execute)
- [Testing](testing)
- [Scheduling](#scheduling)
- [Logging](#logging)
- [Errors](#errors)

# Installation

#### Windows
* Download the [x64 Binary](https://github.com/hornbill/goLDAPUserImport/releases/download/v3.10.0/ldap_user_import_win_x64_v3_10_0.zip) or [x86 Binary](https://github.com/hornbill/goLDAPUserImport/releases/download/v3.10.0/ldap_user_import_win_x86_v3_10_0.zip)
* Extract zip into a folder you would like the application to run from e.g. `C:\LDAP_Import\`
* Configure the Import in Hornbill Administration Tool [See Here](https://wiki.hornbill.com/index.php/LDAP_User_Import)
* Open Command Line Prompt as Administrator
* Change Directory to the folder with ldap_user_import.exe `C:\LDAP_Import\`
* Run the command ldap_user_import.exe -dryrun true -instance $INSTANCEID -apikey $APIKEY

# Config
As of LDAP UserImport 3.0 All Configuration is now done in the Hornbill Administration Tool, [See Here](https://wiki.hornbill.com/index.php/LDAP_User_Import) for details on setting an LDAP User Import configuration

# Execute
Command Line Parameters
* config - Defaults to `` - Id of the Import Configuration to load from Hornbill
* dryrun - Defaults to `false` - Set to True and the XMLMC for Create and Update users will not be called and instead the XML will be dumped to the log file, this is to aid in debugging the initial connection information.
* logprefix - Default to `` - Allows you to define a string to prepend to the name of the log file generated
* instanceid - Default to `` - Id of the Hornbill Instance to Connect to
* apikey - Default to `` - API Key used to Authenticate against Hornbill
* apitimeout - Default to `60` - Number of Seconds to timeout any API Connection
* forcerun - Default to `false` - If a previous run did not successfully complete you can force the next run to bypass the existing running job check

# Testing
If you run the application with the argument dryrun=true then no users will be created or updated, the XML used to create or update will be saved in the log file so you can ensure the LDAP mappings are correct before running the import.

'ldap_user_import.exe -dryrun=true'


# Scheduling

### Windows
You can schedule ldap_user_import.exe to run with any optional command line argument from Windows Task Scheduler.
* Ensure the user account running the task has rights to ldap_import.exe and the containing folder.
* Make sure the Start In parameter contains the folder where ldap_import.exe resides in otherwise it will not be able to pick up the correct path.

# Logging
All Logging output is saved in the log directory in the same directory as the executable the file name contains the date and time the import was run 'LDAP_User_Import_2015-11-06T14-26-13Z.log'

# Errors
* `100` - Unable to create log File
* `101` - Unable to create log folder
* `103` - Unable to Load Configuration No Instance Id
* `104` - Unable to Load Configuration No Api Key
* `105` - Unable to Load Configuration No Configuration Id
* `106` - Unable to Decode Configuration
* `107` - Unable to Load Configuration