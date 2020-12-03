// Copyright 2018 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"time"
)

// Repository is the struct that stores all data from repository to be analyzed.
type Repository struct {
	URL       string    `bson:"repositoryURL" json:"repositoryURL"`
	Branch    string    `json:"repositoryBranch"`
	TimeOut   int       `json:"timeOutInSeconds"`
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`
}

// SecurityTest is the struct that stores all data from the security tests to be executed.
type SecurityTest struct {
	Name             string `bson:"name" json:"name"`
	Image            string `bson:"image" json:"image"`
	ImageTag         string `bson:"imageTag" json:"imageTag"`
	Cmd              string `bson:"cmd" json:"cmd"`
	Type             string `bson:"type" json:"type"`
	Language         string `bson:"language" json:"language"`
	Default          bool   `bson:"default" json:"default"`
	TimeOutInSeconds int    `bson:"timeOutSeconds" json:"timeOutSeconds"`
}

// Analysis is the struct that stores all data from analysis performed.
type Analysis struct {
	RID            string         `bson:"RID" json:"RID"`
	URL            string         `bson:"repositoryURL" json:"repositoryURL"`
	Branch         string         `bson:"repositoryBranch" json:"repositoryBranch"`
	CommitAuthors  []string       `bson:"commitAuthors" json:"commitAuthors"`
	Status         string         `bson:"status" json:"status"`
	Result         string         `bson:"result,omitempty" json:"result"`
	ErrorFound     string         `bson:"errorFound,omitempty" json:"errorFound"`
	Containers     []Container    `bson:"containers" json:"containers"`
	StartedAt      time.Time      `bson:"startedAt" json:"startedAt"`
	FinishedAt     time.Time      `bson:"finishedAt" json:"finishedAt"`
	Codes          []Code         `bson:"codes" json:"codes"`
	HuskyCIResults HuskyCIResults `bson:"huskyciresults,omitempty" json:"huskyciresults"`
}

// Container is the struct that stores all data from a container run.
type Container struct {
	CID          string       `bson:"CID" json:"CID"`
	SecurityTest SecurityTest `bson:"securityTest" json:"securityTest"`
	CStatus      string       `bson:"cStatus" json:"cStatus"`
	COutput      string       `bson:"cOutput" json:"cOutput"`
	CResult      string       `bson:"cResult" json:"cResult"`
	CInfo        string       `bson:"cInfo" json:"cInfo"`
	StartedAt    time.Time    `bson:"startedAt" json:"startedAt"`
	FinishedAt   time.Time    `bson:"finishedAt" json:"finishedAt"`
}

// Code is the struct that stores all data from code found in a repository.
type Code struct {
	Language string   `bson:"language" json:"language"`
	Files    []string `bson:"files" json:"files"`
}

// User is the struct that holds all data from a huskyCI API user
type User struct {
	Username           string `bson:"username" json:"username"`
	Password           string `bson:"password" json:"password"`
	Salt               string `bson:"salt,omitempty" json:"salt"`
	Iterations         int    `bson:"iterations,omitempty" json:"iterations"`
	KeyLen             int    `bson:"keylen,omitempty" json:"keylen"`
	HashFunction       string `bson:"hashfunction,omitempty" json:"hashfunction"`
	NewPassword        string `bson:"newPassword,omitempty" json:"newPassword"`
	ConfirmNewPassword string `bson:"confirmNewPassword,omitempty" json:"confirmNewPassword"`
}

// HuskyCIVulnerability is the struct that stores vulnerability information.
type HuskyCIVulnerability struct {
	Language       string `bson:"language" json:"language,omitempty"`
	SecurityTool   string `bson:"securitytool" json:"securitytool,omitempty"`
	Severity       string `bson:"severity,omitempty" json:"severity,omitempty"`
	Confidence     string `bson:"confidence,omitempty" json:"confidence,omitempty"`
	File           string `bson:"file,omitempty" json:"file,omitempty"`
	Line           string `bson:"line,omitempty" json:"line,omitempty"`
	Code           string `bson:"code,omitempty" json:"code,omitempty"`
	Details        string `bson:"details" json:"details,omitempty"`
	Type           string `bson:"type,omitempty" json:"type,omitempty"`
	Title          string `bson:"title,omitempty" json:"title,omitempty"`
	VunerableBelow string `bson:"vulnerablebelow,omitempty" json:"vulnerablebelow,omitempty"`
	Version        string `bson:"version,omitempty" json:"version,omitempty"`
	Occurrences    int    `bson:"occurrences,omitempty" json:"occurrences,omitempty"`
}

// HuskyCIResults is a struct that represents huskyCI scan results.
type HuskyCIResults struct {
	GoResults         GoResults         `bson:"goresults,omitempty" json:"goresults,omitempty"`
	PythonResults     PythonResults     `bson:"pythonresults,omitempty" json:"pythonresults,omitempty"`
	JavaScriptResults JavaScriptResults `bson:"javascriptresults,omitempty" json:"javascriptresults,omitempty"`
	RubyResults       RubyResults       `bson:"rubyresults,omitempty" json:"rubyresults,omitempty"`
	JavaResults       JavaResults       `bson:"javaresults,omitempty" json:"javaresults,omitempty"`
	HclResults        HclResults        `bson:"hclresults,omitempty" json:"hclresults,omitempty"`
	GenericResults    GenericResults    `bson:"genericresults,omitempty" json:"genericresults,omitempty"`
}

// GoResults represents all Golang security tests results.
type GoResults struct {
	HuskyCIGosecOutput HuskyCISecurityTestOutput `bson:"gosecoutput,omitempty" json:"gosecoutput,omitempty"`
}

// PythonResults represents all Python security tests results.
type PythonResults struct {
	HuskyCIBanditOutput HuskyCISecurityTestOutput `bson:"banditoutput,omitempty" json:"banditoutput,omitempty"`
	HuskyCISafetyOutput HuskyCISecurityTestOutput `bson:"safetyoutput,omitempty" json:"safetyoutput,omitempty"`
}

// JavaScriptResults represents all JavaScript security tests results.
type JavaScriptResults struct {
	HuskyCINpmAuditOutput  HuskyCISecurityTestOutput `bson:"npmauditoutput,omitempty" json:"npmauditoutput,omitempty"`
	HuskyCIYarnAuditOutput HuskyCISecurityTestOutput `bson:"yarnauditoutput,omitempty" json:"yarnauditoutput,omitempty"`
}

// JavaResults represents all Java security tests results.
type JavaResults struct {
	HuskyCISpotBugsOutput HuskyCISecurityTestOutput `bson:"spotbugsoutput,omitempty" json:"spotbugsoutput,omitempty"`
}

// RubyResults represents all Ruby security tests results.
type RubyResults struct {
	HuskyCIBrakemanOutput HuskyCISecurityTestOutput `bson:"brakemanoutput,omitempty" json:"brakemanoutput,omitempty"`
}

// GenericResults represents all generic securityTests results
type GenericResults struct {
	HuskyCIGitleaksOutput HuskyCISecurityTestOutput `bson:"gitleaksoutput,omitempty" json:"gitleaksoutput,omitempty"`
}

// HclResults represents all HCL security tests results.
type HclResults struct {
	HuskyCITFSecOutput HuskyCISecurityTestOutput `bson:"tfsecoutput,omitempty" json:"tfsecoutput,omitempty"`
}

// HuskyCISecurityTestOutput stores all Low, Medium and High vulnerabilities for a sec test
type HuskyCISecurityTestOutput struct {
	NoSecVulns  []HuskyCIVulnerability `bson:"nosecvulns,omitempty" json:"nosecvulns,omitempty"`
	LowVulns    []HuskyCIVulnerability `bson:"lowvulns,omitempty" json:"lowvulns,omitempty"`
	MediumVulns []HuskyCIVulnerability `bson:"mediumvulns,omitempty" json:"mediumvulns,omitempty"`
	HighVulns   []HuskyCIVulnerability `bson:"highvulns,omitempty" json:"highvulns,omitempty"`
}

// TokenRequest defines the JSON struct for an access token request
type TokenRequest struct {
	RepositoryURL string `json:"repositoryURL"`
}

// AccessToken defines the struct generated when a new token
// is requested for specific repository
type AccessToken struct {
	HuskyToken string `bson:"huskytoken" json:"huskytoken"`
}

// DBToken defines the struct that stores husky access token
// for a repository URL
type DBToken struct {
	HuskyToken string    `bson:"huskytoken" json:"huskytoken"`
	URL        string    `bson:"repositoryURL" json:"repositoryURL"`
	IsValid    bool      `bson:"isValid" json:"isValid"`
	CreatedAt  time.Time `bson:"createdAt" json:"createdAt"`
	Salt       string    `bson:"salt" json:"salt"`
	UUID       string    `bson:"uuid" json:"uuid"`
}

// NohuskyFunction represents all the #nohusky verifier methods.
type NohuskyFunction func(string, int) bool
