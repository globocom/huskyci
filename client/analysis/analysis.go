// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/globocom/huskyCI/client/config"
	"github.com/globocom/huskyCI/client/types"
	"github.com/globocom/huskyCI/client/util"
)

// StartAnalysis starts a container and returns its RID and error.
func StartAnalysis() (string, error) {

	// preparing POST to HuskyCI
	huskyStartAnalysisURL := config.HuskyAPI + "/analysis"

	requestPayload := types.JSONPayload{
		RepositoryURL:    config.RepositoryURL,
		RepositoryBranch: config.RepositoryBranch,
		TimeOutInSeconds: config.TimeOutInSeconds,
	}

	marshalPayload, err := json.Marshal(requestPayload)
	if err != nil {
		return "", err
	}

	httpClient, err := util.NewClient(config.HuskyUseTLS)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", huskyStartAnalysisURL, bytes.NewBuffer(marshalPayload))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Husky-Token", config.HuskyToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		if resp.StatusCode == 401 {
			errorMsg := fmt.Sprintf("Unauthorized Husky-Token %s", config.HuskyToken)
			return "", errors.New(errorMsg)
		}
		errorMsg := fmt.Sprintf("Error sending request to start analysis! StatusCode received: %d", resp.StatusCode)
		return "", errors.New(errorMsg)
	}

	RID := resp.Header.Get("X-Request-Id")
	if RID == "" {
		errorMsg := "Error sending request to start analysis. RID is empty!"
		return "", errors.New(errorMsg)
	}

	// Setting analysis values on the JSON output
	outputJSON.Summary.URL = requestPayload.RepositoryURL
	outputJSON.Summary.Branch = requestPayload.RepositoryBranch
	outputJSON.Summary.RID = RID

	return RID, nil
}

// GetAnalysis gets the results of an analysis.
func GetAnalysis(RID string) (types.Analysis, error) {

	analysis := types.Analysis{}
	getAnalysisURL := config.HuskyAPI + "/analysis/" + RID

	httpClient, err := util.NewClient(config.HuskyUseTLS)
	if err != nil {
		return analysis, err
	}

	req, err := http.NewRequest("GET", getAnalysisURL, nil)
	if err != nil {
		return analysis, err
	}

	req.Header.Add("Husky-Token", config.HuskyToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return analysis, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return analysis, err
	}

	err = json.Unmarshal(body, &analysis)
	if err != nil {
		return analysis, err
	}

	return analysis, nil
}

// MonitorAnalysis will keep monitoring an analysis until it has finished or timed out.
func MonitorAnalysis(RID string) (types.Analysis, error) {

	analysis := types.Analysis{}
	timeout := time.After(60 * time.Minute)
	retryTick := time.NewTicker(60 * time.Second)

	for {
		select {
		case <-timeout:
			return analysis, errors.New("time out")
		case <-retryTick.C:
			analysis, err := GetAnalysis(RID)
			if err != nil {
				return analysis, err
			}
			if analysis.Status == "finished" {
				return analysis, nil
			} else if analysis.Status == "error running" {
				return analysis, fmt.Errorf("huskyCI encountered an error trying to execute this analysis: %v", analysis.ErrorFound)
			}
			if !types.IsJSONoutput {
				fmt.Println("[HUSKYCI][!] Hold on! huskyCI is still running...")
			}
		}
	}
}

// PrintResults prints huskyCI output either in JSON or the standard output.
func PrintResults(analysis types.Analysis) error {

	prepareAllSummary(analysis)

	if types.IsJSONoutput {
		err := printJSONOutput()
		if err != nil {
			return err
		}
	} else {
		printSTDOUTOutput(analysis)
	}

	return nil
}
