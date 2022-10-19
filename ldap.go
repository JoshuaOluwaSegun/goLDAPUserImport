package main

import (
	"crypto/tls"
	"fmt"

	"github.com/hornbill/ldap"
)

func connectLDAP() *ldap.LDAPConnection {

	TLSconfig := &tls.Config{
		ServerName:         ldapServerAuth.Host,
		InsecureSkipVerify: ldapImportConf.LDAP.Server.InsecureSkipVerify,
	}
	//-- Based on Connection Type Normal | TLS | SSL
	if ldapImportConf.LDAP.Server.Debug {
		logger(1, "Attempting Connection to LDAP... \nServer: "+ldapServerAuth.Host+"\nPort: "+fmt.Sprintf("%d", ldapServerAuth.Port)+"\nType: "+ldapImportConf.LDAP.Server.ConnectionType+"\nSkip Verify: "+fmt.Sprintf("%t", ldapImportConf.LDAP.Server.InsecureSkipVerify)+"\nDebug: "+fmt.Sprintf("%t", ldapImportConf.LDAP.Server.Debug), true)
	}

	t := ldapImportConf.LDAP.Server.ConnectionType
	switch t {
	case "":
		//-- Normal
		logger(1, "Creating LDAP Connection", false)
		l := ldap.NewLDAPConnection(ldapServerAuth.Host, ldapServerAuth.Port)
		l.Debug = ldapImportConf.LDAP.Server.Debug
		return l
	case "TLS":
		//-- TLS
		logger(1, "Creating LDAP Connection (TLS)", false)
		l := ldap.NewLDAPTLSConnection(ldapServerAuth.Host, ldapServerAuth.Port, TLSconfig)
		l.Debug = ldapImportConf.LDAP.Server.Debug
		return l
	case "SSL":
		//-- SSL
		logger(1, "Creating LDAP Connection (SSL)", false)
		l := ldap.NewLDAPSSLConnection(ldapServerAuth.Host, ldapServerAuth.Port, TLSconfig)
		l.Debug = ldapImportConf.LDAP.Server.Debug
		return l
	}

	return nil
}

// -- Query LDAP
func queryLdap() bool {
	logger(1, "Query LDAP For Users", true)
	//-- Create LDAP Connection
	l := connectLDAP()
	conErr := l.Connect()
	if conErr != nil {
		logger(4, "Connecting Error: "+conErr.Error(), true)
		return false
	}
	defer l.Close()

	//-- Bind
	bindErr := l.Bind(ldapServerAuth.UserName, ldapServerAuth.Password)
	if bindErr != nil {
		logger(4, "Bind Error: "+bindErr.Error(), true)
		return false
	}
	if ldapImportConf.LDAP.Server.Debug {
		logger(1, "LDAP Search Query \n"+fmt.Sprintf("%+v", ldapImportConf.LDAP.Query)+" ----", false)
	}
	//-- Build Search Request
	searchRequest := ldap.NewSearchRequest(
		ldapImportConf.LDAP.Query.DSN,
		ldapImportConf.LDAP.Query.Scope,
		ldapImportConf.LDAP.Query.DerefAliases,
		ldapImportConf.LDAP.Query.SizeLimit,
		ldapImportConf.LDAP.Query.TimeLimit,
		ldapImportConf.LDAP.Query.TypesOnly,
		ldapImportConf.LDAP.Query.Filter,
		ldapImportConf.LDAP.Query.Attributes,
		nil)

	//-- Search Request with 1000 limit pagaing
	results, searchErr := l.SearchWithPaging(searchRequest, 1000)
	if searchErr != nil {
		logger(4, "Search Error: "+searchErr.Error(), true)
		return false
	}

	logger(1, "LDAP Results: "+fmt.Sprintf("%d", len(results.Entries))+"\n", true)
	//-- Catch zero results
	if len(results.Entries) == 0 {
		logger(4, "[LDAP] [SEARCH] No Users Found ", true)
		return false
	}
	ldapUsers = results.Entries
	return true
}
