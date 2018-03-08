package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hornbill/goApiLib"
)

func loadImageFromValue(imageURI string) []byte {

	//-- AD Looking the image URI is binary file so dont try and write that to the log
	if ldapImportConf.User.Image.UploadType != "AD" {
		logger(1, "Image Lookup URI: "+fmt.Sprintf("%s", imageURI), false)
	}
	if strings.ToUpper(ldapImportConf.User.Image.UploadType) != "URL" {
		// get binary to upload via WEBDAV and then set value to relative "session" URI
		var imageB []byte
		var Berr error
		switch strings.ToUpper(ldapImportConf.User.Image.UploadType) {
		//-- Get Local URL
		case "URI":
			//-- Add Support for local HTTPS URLS with invalid cert
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: ldapImportConf.User.Image.InsecureSkipVerify},
			}
			client := &http.Client{Transport: tr}
			resp, err := client.Get(imageURI)
			if err != nil {
				logger(4, "Unable to get image URI: "+imageURI+" ("+fmt.Sprintf("%v", http.StatusInternalServerError)+") ["+fmt.Sprintf("%v", err)+"]", false)
				return nil
			}
			defer resp.Body.Close()
			if resp.StatusCode == 201 || resp.StatusCode == 200 {
				imageB, _ = ioutil.ReadAll(resp.Body)
			} else {
				logger(4, "Unsuccesful download: "+fmt.Sprintf("%v", resp.StatusCode), false)
				return nil
			}
		case "AD":
			imageB = []byte(imageURI)
		default:
			imageB, Berr = hex.DecodeString(imageURI[2:]) //stripping leading 0x
			if Berr != nil {
				logger(4, "Unsuccesful Decoding: "+fmt.Sprintf("%v", Berr), false)
				return nil
			}
		}
		return imageB
	}
	//-- Must be a URL
	response, err := http.Get(ldapImportConf.User.Image.URI)
	if err != nil {
		logger(4, "Unsuccesful Download: "+fmt.Sprintf("%v", err), false)
		return nil
	}
	defer response.Body.Close()
	htmlData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger(4, "Unsuccesful Image Download: "+fmt.Sprintf("%v", err), false)
		return nil
	}
	return htmlData

}

func getImage(importData *userWorkingDataStruct) imageStruct {
	var image imageStruct
	var imageBytes []byte

	//-- Work out the value of URI which may contain [] for LDAP attribute references or just a string
	importData.ImageURI = processComplexFeild(importData.LDAP, ldapImportConf.User.Image.URI)
	//-- Try and Load from Cache
	_, found := HornbillCache.Images[importData.ImageURI]
	if found {
		image = HornbillCache.Images[importData.ImageURI]
	} else {
		//- Load Image if we have one into bytes
		imageBytes = loadImageFromValue(importData.ImageURI)

		//-- Validate Sha1 hex string against what we currently have
		imageCheckSumHex := fmt.Sprintf("%x", sha1.Sum(imageBytes))

		//-- Store in cache
		image.imageBytes = imageBytes
		image.imageCheckSum = imageCheckSumHex
		HornbillCache.Images[importData.ImageURI] = image
	}
	return image
}

func userImageUpdate(hIF *apiLib.XmlmcInstStruct, user *userWorkingDataStruct, buffer *bytes.Buffer) (bool, error) {
	//- Profile Images are already in cache as Bytes
	buffer.WriteString(loggerGen(1, "User Proflile Image Set: "+user.Account.UserID))
	//WebDAV upload
	image := HornbillCache.Images[user.ImageURI]
	value := ""
	relLink := "session/" + user.Account.UserID + "." + ldapImportConf.User.Image.ImageType
	strDAVurl := hIF.DavEndpoint + relLink

	strContentType := "image/jpeg"
	if ldapImportConf.User.Image.ImageType != "jpg" {
		strContentType = "image/png"
	}

	buffer.WriteString(loggerGen(1, "DAV Upload URL: "+fmt.Sprintf("%s", strDAVurl)))

	if Flags.configDryRun != true {

		if len(image.imageBytes) > 0 {
			putbody := bytes.NewReader(image.imageBytes)
			req, Perr := http.NewRequest("PUT", strDAVurl, putbody)
			if Perr != nil {
				return false, Perr
			}
			req.Header.Set("Content-Type", strContentType)
			req.Header.Add("Authorization", "ESP-APIKEY "+Flags.configAPIKey)
			req.Header.Set("User-Agent", "Go-http-client/1.1")
			response, Perr := client.Do(req)
			if Perr != nil {
				return false, Perr
			}
			defer response.Body.Close()
			_, _ = io.Copy(ioutil.Discard, response.Body)
			if response.StatusCode == 201 || response.StatusCode == 200 {
				value = "/" + relLink
			}
		} else {
			buffer.WriteString(loggerGen(1, "Unable to Uplaod Profile Image to Dav as its empty"))
			return true, nil
		}
	}

	buffer.WriteString(loggerGen(1, "Profile Set Image URL: "+fmt.Sprintf("%s", value)))
	hIF.SetParam("objectRef", "urn:sys:user:"+user.Account.UserID)
	hIF.SetParam("sourceImage", value)
	var XMLSTRING = hIF.GetParam()

	if Flags.configDryRun == true {
		buffer.WriteString(loggerGen(1, "Profile Image Set XML "+XMLSTRING))
		hIF.ClearParam()
		return true, nil
	}

	RespBody, xmlmcErr := hIF.Invoke("activity", "profileImageSet")
	var JSONResp xmlmcResponse
	if xmlmcErr != nil {
		buffer.WriteString(loggerGen(1, "Profile Image Set XML "+XMLSTRING))
		return false, xmlmcErr
	}
	err := json.Unmarshal([]byte(RespBody), &JSONResp)
	if err != nil {
		buffer.WriteString(loggerGen(1, "Profile Image Set XML "+XMLSTRING))
		return false, err
	}
	if JSONResp.State.Error != "" {
		buffer.WriteString(loggerGen(1, "Profile Image Set XML "+XMLSTRING))
		return false, errors.New(JSONResp.State.Error)
	}
	buffer.WriteString(loggerGen(1, "Image added to User: "+user.Account.UserID))
	return true, nil
}
