# CHANGELOG

## 3.16.0 (Feburary, 24th, 2022)

Feature:

- Enabled option to upload User images from the local filesystem or network shares.

## 3.15.0 (February 22nd 2023)

Change:

- Complied with latest Go binaries because of security advisory.

## 3.14.0

Feature:

- Added support for setting the following new security settings against imported users:
  - 2 Factor Authentication
  - Disable direct login
  - Disable direct login password reset
  - Disable device pairing on user profile

Change:

- Removed API Key output during tool run
## 3.13.0

Changes:

- Replaced references to deprecated ioutil module with io module
- Added support to clear User Account, User Profile and User Image values using __clear__
- Added auto-update functionality for minor & patch version changes
- General tidy up

Fix:

- Issue where changes to Social Network fields E & F would not trigger a user profile update

## 3.12.0

Change:

- Added ability to "calculate" objectGUID - needs option in LDAP Import Configuration

## 3.11.0

Fix:

- Issue with attributes not comparing correctly

## 3.10.0

Change:

- Improved performance when caching user account groups

## 3.9.6

Change:

- Modification such that a calculated field can be used as User ID (eg Object SID)

## 3.9.5

Change:

- Rebuilt using latest version of goApiLib, to fix possible issue with connections via a proxy

##�3.9.4

Fixed:

- Issue returning counts of roles and groups associated with users, values were too large to be parsed into 16 bit integer, upped the parser definition to 64 bit.

## 3.9.3

Fixed:

- Issue with count struct

## 3.9.2

Change:

- Improved logging when getting counts of data lists to cache

## 3.9.1

Change:

- Improved logging when user account or profile record is being updated

Fixed:

- Issue where manager is not updated when job description or middle name was being set against profile

## 3.9.0

Change:

- Added support for Object SID Conversion as a Pre Import Action

## 3.8.2

Reverted:

- User Profile was not always being created on user creation (it is likely a timing problem (user profile update run before the user creation has fully completed)). Reverted back to pre-3.7.1 behaviour in which only user updates populate the profiles.

## 3.8.1

Fixed:

- If new user record creation errors for whatever reason, the tool now no longer attempts to update the users profile, which can cause broken user records to be created.

## 3.8.0

Changes:

- Added support to define if users should be created, updated or both

## 3.7.3 (June 17th, 2020)

Changes:

- Improved error reporting when blacklist cannot be retrieved

## 3.7.2 (June 12th, 2020)

Changes:

- minor changes to be compatible with new crosscompile script

## 3.7.1 (June 5th, 2020)

Fixes:

- User Profile is set on account creation (instead of only modified on account update)

## 3.7.0 (June 2nd, 2020)

Fixes:

- Improved error output when the tool is unable to talk to Hornbill and/or Github
- Fixed issue updating users where the loginId value has not changed.

## 3.6.2 (April 22nd, 2020)

Fix:

- Issue when loading configuration

## 3.6.1 (April 15th, 2020)

Change:

- Updated code to support Core application and platform changes

## 3.6.0 (March 11th, 2020)

Changes:

- Added support for converting LDAP/FILETIME timestamps to human and database readable datetime stamp

## 3.5.0 (January 9th, 2020)

Changes:

- Added support for new Employee ID field in user record

## 3.4.0 (November 18th, 2019)

Changes:

- Added support for new Login ID field in user record
- Corrected minor spelling mistakes

## 3.3.0 (October 18th, 2019)

Changes:

- Added feature to allow the setting of a Home Organisation when creating/updating users

## 3.2.1 (July 3rd, 2019)

Changes:

- Updated password generation code to support update to Hornbill Password Generator module

## 3.2.0 (May 29, 2019)

Changes:

- Updated user password generation code to enforce Hornbill instance user password profile settings

## 3.1.5 (Mar 29, 2019)

Bug Fixes:

- Group mapping incorrect when there are groups of different types with the same display name
- Issue with incorrect status type returned while retrieving LDAP key
- Outcome issue with `Trim` pre-import action

Changes:

- Removed unnecessary vars and structs
- Added code to remove image file from ESP session once attached

## 3.1.4 (Nov 9th, 2018)

Bug Fix:

- FIX: Tool would not import images from AD source

## 3.1.3 (Aug 14 , 2018)

Features:

- ADD: Pre Import Actions now support 'Trim' which removes white space arround the string and any new lines

## 3.1.2 (Aug 13 , 2018)

Bug Fixes:

- FIX: Invalid Regex would cause a crash on the import, now any invalid regex matches are thrown as Errors in the log.

## 3.1.1 (Jul 27 , 2018)

Bug Fixes:

- FIX: Regex match will now return the first match with a result as apposed to the last match if one or more matches are found.

## 3.1.0 (Jul 19 , 2018)

Features:

- ADD: It's now possible to define Pre Import Actions on a value or LDAP Attribute or the output of a previous Pre Import Actions, these allow Regex matches and string replaces to performed on a given value and stored for use anyway in the Import Configuration.

## 3.0.8 (Jul 4 , 2018)

Bug Fixes:

- FIX: Panic when loading previous import history for the first time.

## 3.0.7 (Jul 2 , 2018)

Bug Fixes:

- FIX: In the event a Load Data count could not be returned log the error and return 0
- FIX: In debug log each count from Load Data

## 3.0.6 (Jul 1 , 2018)

Bug Fixes:

- FIX: Issue where loading pages of data could exceed the total data count and continue for ever, added handeling for breaking out of the loop when no data is returned from a paged query.
- FIX: Prevent an import running if an existing import of the same configuration is in progress, input flag added to over ride the behviour if needed (e.g when a server loses connection mid import and can not update its status to complete or failed)

## 3.0.5 (Jun 21 , 2018)

Bug Fixes:

- FIX: OnlyOneGroupAssignment property was not correctly being processed causing groups to be removed from users randomly when this setting was enabled. This now allows you define against a group that only one group of the defined type will be assigned to a user, any groups found to be assigned to the user of the same type will be removed leaving only the group set with OnlyOneGroupAssignment on the import configuration. Groups of a different type will not be removed.

## 3.0.4 (May 31 , 2018)

Bug Fixes:

- FIX: LDAP Users with prefixed or trailing white spaces were not handled correctly

## 3.0.3 (Apr 11 , 2018)

Bug Fixes:

- FIX: Ability to set User Account Status was none functional

## 3.0.2 (Apr 10 , 2018)

Bug Fixes:

- FIX: Ability to set the HTTP Connection timeout was missed when Uploading Images

## 3.0.1 (Apr 3 , 2018)

Features:

- ADD: Ability to set the HTTP Connection timeout on any Hornbill API Call (Default 60 Seconds)

## 3.0.0 (Mar 11 , 2018)

Features:

- ADD: Ability to assign one or more Organisations to a user
- ADD: Ability to filter user Organisation assignment based on the memberof attribtute in LDAP "MemberOf" added to the Organisation configuration that should match the name of the AD a User should be in before the Organisation is assinged.
- ADD: LogLevel has been added which defaults to 2 (Message, Warning, Error), this can be changed to 1 (Debug, Message, Warning, Error) if additional debug logging is required
- ADD: Dry Run XML Output is now formatted better in the log file
- ADD: Log File Retention (Set to 0 By Default) Can be set to the maximum number of days to keep local log files for.
- ADD: Release Binarys are now built for Windows (x86 & x64), Linux (x86 & x64 & ARM), OSX (x86 & x64)

- CHANGE: Import Configuration is now loaded from the Instance and not via a local JSON file, this is to provide a user freindly UI for generating the configuration.
- CHANGE: The tool has been completely rewritten to be more efficient this will have a drematic effect on the time taken for the tool to run (In a Postitve way)
- CHANGE: The log output has been updated to closer reflect how the tool is processing data the format is still (YYYY/MM/DD HH:MM:SS [LogLevel] Message)
- CHANGE: The tool no longer writea a log file to your hornbill instance instead a History Table is maintained linked to the Import Configuration so a history of the imports run can be seen in the Imports Configuration UI in the Hornbill Administration Tool.

## 2.4.2 (Feb 1 , 2018)

Features:

- ADD: "SearchforManager" added to Manager Mapping configuration allowing you to disable the search for a managers userId if you already have the value from an LDAP Attribute.

## 2.4.1 (Sep 20 , 2017)

Bug Fixes:

- FIX: Error setting User Status and Import Status following previous change

## 2.4.0 (Sep 11 , 2017)

Features:

- ADD: It is now possible to overwrite group assignments to a user based on a specific type i.e users can only be assigned to one department and existing associations that do not match the updated associate that is to be made will be removed.

Bug Fixes:

- FIX: Concurrency issue when assigning users to a group

## 2.3.1 (Sep 11 , 2017)

Bug Fixes:

- FIX: Manager Lookup Cache is build before users are processed.

## 2.3.0 (Sep 11 , 2017)

Features:

- ADD: Ability to Cache users and their DN to use for Manager lookups

## 2.2.2 (Sep 11 , 2017)

Bug Fixes:

- FIX: thumbnailPhoto in default configuration should now be [thumbnailPhoto] for Image Uploads

## 2.2.1 (Aug 30 , 2017)

Bug Fixes:

- FIX: Issue with Manager lookup following 2.2.0 changes

## 2.2.0 (Aug 30 , 2017)

Features:

- CHANGE: Remove -zone flag and look up correctly using instanceID
- CHANGE: -workers flag now default to 10 not 1 to improve performance

Bug Fixes:

- FIX: Profile Image Upload now correctly support URL (Public) and URI (Internal) Images as well as AD Binary images
- FIX: Manage Import can now correctly be earched on any user profile feild not just h_name

## 2.1.1 (Aug 30 , 2017)

Bug Fixes:

- FIX: Improve mutithreaded performance
- FIX: Improve http request pool
- FIX: Issue importing profile image from URI

## 2.1.0 (May 2 , 2017)

Features:

- ADD: Profile images

## 2.0.6 (Jan 5 , 2017)

Features:

- ADD: Further debugging for LDAP Manager Lookups

Bug Fixes:

- Fix: Issue where if the Manager Import action was set to Update then the import would not process Managers

## 2.0.5 (Oct 17 , 2016)

Features:

- ADD: Validate LDAP Server ConnectionType, an invalid connection type would cause a panic in the LDAP Library.

Bug Fixes:

- Fix: Performance Issue with number of HTTP Connections being created

## 2.0.4 (Aug 4 , 2016)

Features:

- ADD: New Input flag `-logprefix=` which allows you to append a string to the name of the log file generated

## 2.0.3 (May 18 , 2016)

Bug Fixes:

- Fix: Hardcoded number of records that would be processed to 100, removed total is now taken from results from LDAP

## 2.0.2 (May 18 , 2016)

Bug Fixes:

- Fix: Attributes for user Profile were not being populated correctly
- Fix: Potential Race conditions after moving to Goroutines
- FIX: Reduce Potential for any errors and default workers back to 1

## 2.0.1 (May 18 , 2016)

Features:

- ADD: Ability to assign roles to a user on user update

Bug Fixes:

- Fix: conf.json was invalid
- Fix: Potential Race conditions after moving to Goroutines

## 2.0.0 (May 11 , 2016)

Features:

- ADD Support for APIKeys instead of username and password for Authentication to Hornbill
- ADD Concurrent workers, this should improve performance on large imports -workers input flag allows you to override the default of 3
- User Profile Extended Detail Support has been added
- Ability to define what actions should cause Site and Organisations to be associate (On Create | On Update | Both)
- ADD Ability to set a user account status (On Create | On Update | Both)
- ADD Ability to Lookup Manager Name from LDAP Field and map to Hornbill User Id UserManagerMapping

Bug Fixes:

- Fix: Timetaken was not being reported in the ESP Log File
- Fix: Version was not being reported in the ESP Log File
- Fix: HTML Entities were not correct decoded when returned from an LDAP string
- Fix: SiteLookup.Attribute was not expecting LDAP Attributes to be wrapped in [ ] like OrgLookup.Attribute this has been changed for consistency with other LDAP Attributes

Notes:

- The conf.json has been altered so some of the property names like LDAPMapping not correctly reflect there purpose LDAPMApping is now UserMapping the content of this configuration is the same and can be copied from your previous configuration file.

- UserID and Password for you Hornbill Instance is no longer used, you will need to generate an APIKey in the Administration Tool via the User Details - There is now a new tab called API Keys which allow you to generate an API key for a user, this should be done against which ever user account was previously used for the imports.

## 1.7.0 (March 18 , 2016)

Features:

- ADD Organization Lookup when Creating / Updating Users.

## 1.6.2 (March 16 , 2016)

Features:

- ADD Debug LDAP Connection to aid with troubleshooting.

## 1.6.1 (March 2 , 2016)

Bug Fixes:

- Fix SAMAccountName was hardcoded as the userId when checking if a user existed in hornbill

## 1.6.0 (Feburary 25 , 2016)

Features:

- GoLang upgraded to 1.6
- Added support for SSL/TLS connections to LDAP server

## 1.5.3 (Feburary 16 , 2016)

Features:

- Errors are now displayed in red in the console.
- Checks for mandatory values from the configuration file are now done before processing begins.
- Check for latest version will now display in the console and log on startup of the process

Bug Fixes:

- HTTP Client ignores environmental http proxy and https proxy settings
- Better Error handling and XMLMC lib cannot connect to the API Endpoint

## 1.5.2 (Feburary 8, 2016)

Bug Fixes:

- Add additional logging to the login script.

## 1.5.1 (January 8, 2016)

Features:

- CH00138411 - Expose further LDAP Search Configuration options to the Configuration File
- LDAP Search Query is now saved to the Log file
- Errors Creating / Updating Users as well as Assigning Roles are returned to the Hornbill Log File for easier Diagnostics

Bug Fixes:

- Prevent `<invalid Value>` from being used as a value when an LDAP Attribute cannot be found and instead a Error in the log is written.
- Errors while create / Updating users are no loner output to the console breaking the progress bar and instead an error count is output at
the end of the process and will refer the user to the Log File.
Notes:

- The following should be added to the "LDAPConf" section of the configuration file for searching to operate as previous.

"Scope": 1,
"DerefAliases": 1,

## 1.5.0 (December 18, 2015)

Bug Fixes:

- UserID was incorrectly referenced as UserId after some code refactoring
- UpdateUserType was missing from the default configuration

## 1.4.1 (December 14, 2015)

Features:

- Released to GitHub

## 1.4.0 (December 08, 2015)

Features:

- Ability to prevent userType from being updated

## 1.3.0 (December 07, 2015)

Features:

- Updated External Library (ApiLib)
- Added Debugging for LDAP Returned Data

Bug Fixes:

- Phone Attribute on User Create/Update was not being set

## 1.2.0 (February 17, 2010)

Features:

- ESP Logging to Aid Support
- Ability to Lookup Site

Bug Fixes:

- Unable to Load Configuration from -file flag

## 1.1.0 (November 9, 2015)

Features:

- Assigning Roles when a user is created

## 1.0.0 (November 9, 2015)

Features:

- Initial Release
