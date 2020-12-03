// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

// FoundVuln is the boolean that will be checked to return an os.exit(0) or os.exit(1)
var FoundVuln bool

// FoundInfo is the boolean that will be checked to verify if only low/info severity vulnerabilites were found.
var FoundInfo bool

// IsJSONoutput is the boolean that will be checked to verity if the output is expected to be printed in a JSON format
var IsJSONoutput bool

// JSONPayload is a struct that represents the JSON payload needed to make a HuskyCI API request.
type JSONPayload struct {
	RepositoryURL    string `json:"repositoryURL"`
	RepositoryBranch string `json:"repositoryBranch"`
	TimeOutInSeconds int    `json:"timeOutInSeconds"`
}

// Target is the struct that represents HuskyCI API target
type Target struct {
	Label        string
	Endpoint     string
	TokenStorage string
	Token        string
}

// Analysis is the struct that stores all data from analysis performed.
type Analysis struct {
	ID             bson.ObjectId  `bson:"_id,omitempty"`
	RID            string         `bson:"RID" json:"RID"`
	URL            string         `bson:"repositoryURL" json:"repositoryURL"`
	Branch         string         `bson:"repositoryBranch" json:"repositoryBranch"`
	Status         string         `bson:"status" json:"status"`
	Result         string         `bson:"result" json:"result"`
	Containers     []Container    `bson:"containers" json:"containers"`
	ErrorFound     string         `bson:"errorFound" json:"errorFound"`
	StartedAt      time.Time      `bson:"startedAt" json:"startedAt"`
	FinishedAt     time.Time      `bson:"finishedAt" json:"finishedAt"`
	Codes          []Code         `bson:"codes" json:"codes"`
	HuskyCIResults HuskyCIResults `bson:"huskyciresults,omitempty" json:"huskyciresults"`
}

// Code is the struct that stores all data from code found in a repository.
type Code struct {
	Language string   `bson:"language" json:"language"`
	Files    []string `bson:"files" json:"files"`
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

// SecurityTest is the struct that stores all data from the security tests to be executed.
type SecurityTest struct {
	ID               bson.ObjectId `bson:"_id,omitempty"`
	Name             string        `bson:"name" json:"name"`
	Image            string        `bson:"image" json:"image"`
	ImageTag         string        `bson:"imageTag" json:"imageTag"`
	Cmd              string        `bson:"cmd" json:"cmd"`
	Language         string        `bson:"language" json:"language"`
	Default          bool          `bson:"default" json:"default"`
	TimeOutInSeconds int           `bson:"timeOutSeconds" json:"timeOutSeconds"`
}

// HuskyCIVulnerability is the struct that stores vulnerability information.
type HuskyCIVulnerability struct {
	Language       string `json:"language,omitempty"`
	SecurityTool   string `json:"securitytool,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Confidence     string `json:"confidence,omitempty"`
	File           string `json:"file,omitempty"`
	Line           string `json:"line,omitempty"`
	Code           string `json:"code,omitempty"`
	Details        string `json:"details,omitempty"`
	Type           string `json:"type,omitempty"`
	Title          string `json:"title,omitempty"`
	VunerableBelow string `json:"vulnerablebelow,omitempty"`
	Version        string `json:"version,omitempty"`
	Occurrences    int    `json:"occurrences,omitempty"`
}

// JSONOutput is a truct that represents huskyCI output in a JSON format.
type JSONOutput struct {
	GoResults         GoResults         `json:"goresults,omitempty"`
	PythonResults     PythonResults     `json:"pythonresults,omitempty"`
	JavaScriptResults JavaScriptResults `json:"javascriptresults,omitempty"`
	RubyResults       RubyResults       `json:"rubyresults,omitempty"`
	JavaResults       JavaResults       `json:"javaresults,omitempty"`
	HclResults        HclResults        `json:"hclresults,omitempty"`
	GenericResults    GenericResults    `json:"genericresults,omitempty"`
	Summary           Summary           `json:"summary,omitempty"`
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

// GenericResults represents all generic securityTests results.
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

// Summary holds a summary of the information on all security tests.
type Summary struct {
	URL              string         `json:"repositoryURL"`
	Branch           string         `json:"repositoryBranch"`
	RID              string         `json:"RID"`
	GosecSummary     HuskyCISummary `json:"gosecsummary,omitempty"`
	BanditSummary    HuskyCISummary `json:"banditsummary,omitempty"`
	SafetySummary    HuskyCISummary `json:"safetysummary,omitempty"`
	NpmAuditSummary  HuskyCISummary `json:"npmauditsummary,omitempty"`
	YarnAuditSummary HuskyCISummary `json:"yarnauditsummary,omitempty"`
	BrakemanSummary  HuskyCISummary `json:"brakemansummary,omitempty"`
	SpotBugsSummary  HuskyCISummary `json:"spotbugssummary,omitempty"`
	GitleaksSummary  HuskyCISummary `json:"gitleakssummary,omitempty"`
	TFSecSummary     HuskyCISummary `json:"tfsecsummary,omitempty"`
	TotalSummary     HuskyCISummary `json:"totalsummary,omitempty"`
}

// HuskyCISummary is the struct that holds summary information.
type HuskyCISummary struct {
	FoundVuln  bool `json:"foundvuln,omitempty"`
	FoundInfo  bool `json:"foundinfo,omitempty"`
	NoSecVuln  int  `json:"nosecvuln,omitempty"`
	LowVuln    int  `json:"lowvuln,omitempty"`
	MediumVuln int  `json:"mediumvuln,omitempty"`
	HighVuln   int  `json:"highvuln,omitempty"`
}
