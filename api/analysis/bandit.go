// Copyright 2018 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/globocom/huskyCI/api/db"
	"github.com/globocom/huskyCI/api/log"
	"github.com/globocom/huskyCI/api/types"
	"gopkg.in/mgo.v2/bson"
)

// BanditOutput is the struct that holds all data from Bandit output.
type BanditOutput struct {
	Errors  json.RawMessage `json:"errors"`
	Results []Result        `json:"results"`
}

// Result is the struct that holds detailed information of issues from Bandit output.
type Result struct {
	Code            string `json:"code"`
	Filename        string `json:"filename"`
	IssueConfidence string `json:"issue_confidence"`
	IssueSeverity   string `json:"issue_severity"`
	IssueText       string `json:"issue_text"`
	LineNumber      int    `json:"line_number"`
	LineRange       []int  `json:"line_range"`
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
}

// BanditStartAnalysis analyses the output from Bandit and sets a cResult based on it.
func BanditStartAnalysis(CID string, cOutput string, RID string) {

	analysisQuery := map[string]interface{}{"containers.CID": CID}

	// error cloning repository!
	if strings.Contains(cOutput, "ERROR_CLONING") {
		errorOutput := fmt.Sprintf("Container error: %s", cOutput)
		updateContainerAnalysisQuery := bson.M{
			"$set": bson.M{
				"containers.$.cResult": "error",
				"containers.$.cInfo":   errorOutput,
			},
		}
		err := db.UpdateOneDBAnalysisContainer(analysisQuery, updateContainerAnalysisQuery)
		if err != nil {
			log.Error("BanditStartAnalysis", "BANDIT", 2007, "Step 1", err)
		}
		return
	}

	var banditResult BanditOutput
	if err := json.Unmarshal([]byte(cOutput), &banditResult); err != nil {
		log.Error("BanditStartAnalysis", "BANDIT", 1006, cOutput, err)
		return
	}

	// Sets the container output to "No issues found" if banditResult returns an empty slice
	if len(banditResult.Results) == 0 {
		updateContainerAnalysisQuery := bson.M{
			"$set": bson.M{
				"containers.$.cResult": "passed",
				"containers.$.cInfo":   "No issues found.",
			},
		}
		err := db.UpdateOneDBAnalysisContainer(analysisQuery, updateContainerAnalysisQuery)
		if err != nil {
			log.Error("BanditStartAnalysis", "BANDIT", 2007, "Step 1,5", err)
		}
		return
	}

	// verify if there was any error in the analysis.
	if banditResult.Errors != nil {
		updateContainerAnalysisQuery := bson.M{
			"$set": bson.M{
				"containers.$.cResult": "error",
			},
		}
		err := db.UpdateOneDBAnalysisContainer(analysisQuery, updateContainerAnalysisQuery)
		if err != nil {
			log.Error("BanditStartAnalysis", "BANDIT", 2007, "Step 2", err)
		}
	}

	// find Issues that have severity "MEDIUM" or "HIGH" and confidence "HIGH".
	cResult := "passed"
	for _, issue := range banditResult.Results {
		if (issue.IssueSeverity == "HIGH" || issue.IssueSeverity == "MEDIUM") && issue.IssueConfidence == "HIGH" {
			cResult = "failed"
			break
		}
	}

	// update the status of analysis.
	issueMessage := "No issues found."
	if cResult != "passed" {
		issueMessage = "Issues found."
	}
	updateContainerAnalysisQuery := bson.M{
		"$set": bson.M{
			"containers.$.cResult": cResult,
			"containers.$.cInfo":   issueMessage,
		},
	}
	if err := db.UpdateOneDBAnalysisContainer(analysisQuery, updateContainerAnalysisQuery); err != nil {
		log.Error("BanditStartAnalysis", "BANDIT", 2007, "Step 3", err)
		return
	}

	// get updated analysis based on its RID
	analysisQuery = map[string]interface{}{"RID": RID}
	analysis, err := db.FindOneDBAnalysis(analysisQuery)
	if err != nil {
		log.Error("GosecStartAnalysis", "BANDIT", 2008, CID, err)
		return
	}

	// finally, update analysis with huskyCI results
	analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput = prepareHuskyCIBanditOutput(banditResult)
	err = db.UpdateOneDBAnalysis(analysisQuery, analysis)
	if err != nil {
		log.Error("GosecStartAnalysis", "BANDIT", 2007, err)
		return
	}

}

// prepareHuskyCIBanditOutput will prepare Bandit output to be added into pythonResults struct
func prepareHuskyCIBanditOutput(banditOutput BanditOutput) types.HuskyCIBanditOutput {

	var huskyCIbanditResults types.HuskyCIBanditOutput

	for _, issue := range banditOutput.Results {
		banditVuln := types.HuskyCIVulnerability{}
		banditVuln.Language = "Python"
		banditVuln.SecurityTool = "Bandit"
		banditVuln.Severity = issue.IssueSeverity
		banditVuln.Confidence = issue.IssueConfidence
		banditVuln.Details = issue.IssueText
		banditVuln.File = issue.Filename
		banditVuln.Line = strconv.Itoa(issue.LineNumber)
		banditVuln.Code = issue.Code

		switch banditVuln.Severity {
		case "LOW":
			huskyCIbanditResults.LowVulnsBandit = append(huskyCIbanditResults.LowVulnsBandit, banditVuln)
		case "MEDIUM":
			huskyCIbanditResults.MediumVulnsBandit = append(huskyCIbanditResults.MediumVulnsBandit, banditVuln)
		case "HIGH":
			huskyCIbanditResults.HighVulnsBandit = append(huskyCIbanditResults.HighVulnsBandit, banditVuln)
		}
	}

	return huskyCIbanditResults
}
