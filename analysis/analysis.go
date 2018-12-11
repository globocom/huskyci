// Copyright 2018 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/globocom/glbgelf"
	"github.com/globocom/huskyci/types"
	"github.com/labstack/echo"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// Version holds the API version to be returned in /version route.
var Version types.VersionAPI

// HealthCheck is the heath check function.
func HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING!\n")
}

//VersionHandler returns the API version
func VersionHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, Version)
}

// ReceiveRequest receives the request and performs several checks before starting a new analysis.
func ReceiveRequest(c echo.Context) error {
	RID := c.Response().Header().Get(echo.HeaderXRequestID)

	// check-00: is this a valid JSON?
	repository := types.Repository{}
	err := c.Bind(&repository)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Error binding repository."})
	}

	// check-01: is this a git repository URL and a branch?
	regexpGit := `((git|ssh|http(s)?)|(git@[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/)?`
	r := regexp.MustCompile(regexpGit)
	valid, err := regexp.MatchString(regexpGit, repository.URL)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Internal error."})
	}
	if !valid {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "This is not a valid repository URL."})
	}
	matches := r.FindString(repository.URL)
	repository.URL = matches

	regexpBranch := `^[a-zA-Z0-9_\.-]*$`
	valid, err = regexp.MatchString(regexpBranch, repository.Branch)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Internal error."})
	}
	if !valid {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "This is not a valid branch."})
	}

	// check-02: is this repository in MongoDB?
	repositoryQuery := map[string]interface{}{"repositoryURL": repository.URL, "repositoryBranch": repository.Branch}
	repositoryResult, err := FindOneDBRepository(repositoryQuery)
	if err == nil {
		// check-03: repository found! does it have a running status analysis? (for the future: check commits and not URLs?)
		analysisQuery := map[string]interface{}{"repositoryURL": repository.URL, "repositoryBranch": repository.Branch}
		analysisResult, err := FindOneDBAnalysis(analysisQuery)
		if err != mgo.ErrNotFound {
			if analysisResult.Status == "running" {
				return c.JSON(http.StatusConflict, map[string]string{"result": "error", "details": "An analysis is already in place for this URL."})
			}
		}
	} else {
		// repository not found! insert it into MongoDB with default securityTests
		err = InsertDBRepository(repository)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"result": "error", "details": "Internal error inserting repository."})
		}
		repositoryQuery := map[string]interface{}{"repositoryURL": repository.URL, "repositoryBranch": repository.Branch}
		repositoryResult, err = FindOneDBRepository(repositoryQuery)
		if err != nil {
			// well it was supposed to be there, after all, we just inserted it.
			return c.JSON(http.StatusInternalServerError, map[string]string{"result": "error", "details": "Internal error finding repository."})
		}
	}

	go StartAnalysis(RID, repositoryResult)

	return c.JSON(http.StatusOK, map[string]string{"RID": RID, "result": "ok", "details": "Request received."})
}

// StartAnalysis starts the analysis given a RID and a repository.
func StartAnalysis(RID string, repository types.Repository) {

	// step 0: create a new analysis struct
	newAnalysis := types.Analysis{
		RID:        RID,
		URL:        repository.URL,
		Branch:     repository.Branch,
		Status:     "running",
		Containers: make([]types.Container, 0),
	}

	// step 1: insert new analysis into MongoDB.
	err := InsertDBAnalysis(newAnalysis)
	if err != nil {
		if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
			"action": "StartAnalysis",
			"info":   "ANALYSIS"}, "ERROR", "Error inserting new analysis.", err); errLog != nil {
			fmt.Println("glbgelf error: ", errLog)
		}
		return
	}

	// step 2: start enry and EnryStartAnalysis will start all others securityTests
	enryQuery := map[string]interface{}{"name": "enry"}
	enrySecurityTest, err := FindOneDBSecurityTest(enryQuery)
	if err != nil {
		if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
			"action": "StartAnalysis",
			"info":   "ANALYSIS"}, "ERROR", "Error finding Enry SecurityTest:", err); errLog != nil {
			fmt.Println("glbgelf error: ", errLog)
		}
		return
	}
	DockerRun(RID, &newAnalysis, enrySecurityTest)

	// step 3: worker will check if jobs are done to set newAnalysis.Status = "finished".
	go MonitorAnalysis(&newAnalysis)

}

// MonitorAnalysis querys an analysis every retryTick seconds to check if it has already finished.
func MonitorAnalysis(analysis *types.Analysis) {

	timeout := time.After(10 * time.Minute)
	retryTick := time.Tick(5 * time.Second)

	for {
		select {
		case <-timeout:
			// cenario 1: MonitorAnalysis has timed out!
			if err := monitorAnalysisTimedOut(analysis.RID); err != nil {
				if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
					"action": "MonitorAnalysis",
					"info":   "ANALYSIS"}, "ERROR", "Internal error monitorAnalysisTimedOut(): ", err); errLog != nil {
					fmt.Println("glbgelf error: ", errLog)
				}
				return
			}
			return
		case <-retryTick:
			// check if analysis has already finished.
			analysisHasFinished, err := monitorAnalysisCheckStatus(analysis.RID)
			if err != nil {
				if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
					"action": "MonitorAnalysis",
					"info":   "ANALYSIS"}, "ERROR", "Internal error monitorAnalysisCheckStatus(): ", err); errLog != nil {
					fmt.Println("glbgelf error: ", errLog)
				}
			}
			// cenario 2: analysis has finished!
			if analysisHasFinished {
				err := monitorAnalysisUpdateStatus(analysis.RID)
				if err != nil {
					if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
						"action": "MonitorAnalysis",
						"info":   "ANALYSIS"}, "ERROR", "Internal error monitorAnalysisUpdateStatus(): ", err); errLog != nil {
						fmt.Println("glbgelf error: ", errLog)
					}
				}
			} // cenario 3: retry after retryTick seconds!
		}
	}

}

// monitorAnalysisTimedOut updates the status of a given analysis to "timedout".
func monitorAnalysisTimedOut(RID string) error {
	analysisQuery := map[string]interface{}{"RID": RID}
	updateAnalysisQuery := bson.M{
		"$set": bson.M{
			"status": "timedout",
		},
	}
	err := UpdateOneDBAnalysisContainer(analysisQuery, updateAnalysisQuery)
	if err != nil {
		if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
			"action": "monitorAnalysisTimedOut",
			"info":   "ANALYSIS"}, "ERROR", "Error updating AnalysisCollection:", err); errLog != nil {
			fmt.Println("glbgelf error: ", errLog)
		}
	}
	return err
}

// monitorAnalysisUpdateStatus updates status and result of a given analysis.
func monitorAnalysisUpdateStatus(RID string) error {
	analysisQuery := map[string]interface{}{"RID": RID}
	analysisResult, err := FindOneDBAnalysis(analysisQuery)
	if err != nil {
		if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
			"action": "monitorAnalysisUpdateStatus",
			"info":   "ANALYSIS"}, "ERROR", "Could not find analysis:", err); errLog != nil {
			fmt.Println("glbgelf error: ", errLog)
		}
		return err
	}
	// analyze each cResult from each container to determine what is the value of analysis.Result
	finalResult := "passed"
	for _, container := range analysisResult.Containers {
		if container.CResult == "failed" {
			finalResult = "failed"
			break
		}
	}
	updateAnalysisQuery := bson.M{
		"$set": bson.M{
			"status": "finished",
			"result": finalResult,
		},
	}
	err = UpdateOneDBAnalysisContainer(analysisQuery, updateAnalysisQuery)
	if err != nil {
		if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
			"action": "monitorAnalysisUpdateStatus",
			"info":   "ANALYSIS"}, "ERROR", "Error updating AnalysisCollection:", err); errLog != nil {
			fmt.Println("glbgelf error: ", errLog)
		}
	}
	return err
}

// monitorAnalysisCheckStatus checks if an analysis has already finished and returns the correspoding boolean.
func monitorAnalysisCheckStatus(RID string) (bool, error) {
	analysisFinished := false
	analysisQuery := map[string]interface{}{"RID": RID}
	analysisResult, err := FindOneDBAnalysis(analysisQuery)
	if err != nil {
		if errLog := glbgelf.Logger.SendLog(map[string]interface{}{
			"action": "monitorAnalysisCheckStatus",
			"info":   "ANALYSIS"}, "ERROR", "Could not find analysis:", err); errLog != nil {
			fmt.Println("glbgelf error: ", errLog)
		}
	}
	for _, container := range analysisResult.Containers {
		if container.CStatus != "finished" {
			analysisFinished = false
			break
		} else {
			analysisFinished = true
		}
	}
	return analysisFinished, err
}

// StatusAnalysis returns the status of a given analysis (via RID).
func StatusAnalysis(c echo.Context) error {
	RID := c.Param("id")
	analysisQuery := map[string]interface{}{"RID": RID}
	analysisResult, err := FindOneDBAnalysis(analysisQuery)
	if err == mgo.ErrNotFound {
		return c.JSON(http.StatusNotFound, map[string]string{"result": "error", "details": "Analysis not found."})
	} // What if DB is not reachable!? else { }
	return c.JSON(http.StatusOK, analysisResult)
}

// CreateNewSecurityTest inserts the given securityTest into SecurityTestCollection.
func CreateNewSecurityTest(c echo.Context) error {
	securityTest := types.SecurityTest{}
	err := c.Bind(&securityTest)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Error binding securityTest."})
	}

	securityTestQuery := map[string]interface{}{"name": securityTest.Name}
	_, err = FindOneDBSecurityTest(securityTestQuery)
	if err != mgo.ErrNotFound {
		return c.JSON(http.StatusConflict, map[string]string{"result": "error", "details": "This securityTest is already in MongoDB."})
	}

	err = InsertDBSecurityTest(securityTest)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"result": "error", "details": "Error creating new securityTest."})
	}

	return c.JSON(http.StatusCreated, map[string]string{"result": "created", "details": "securityTest sucessfully created."})
}

// CreateNewRepository inserts the given repository into RepositoryCollection.
func CreateNewRepository(c echo.Context) error {
	repository := types.Repository{}
	err := c.Bind(&repository)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"result": "error", "details": "Error binding repository."})
	}

	repositoryQuery := map[string]interface{}{"URL": repository.URL}
	_, err = FindOneDBRepository(repositoryQuery)
	if err == nil {
		return c.JSON(http.StatusConflict, map[string]string{"result": "error", "details": "Repository found."})
	}

	err = InsertDBRepository(repository)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"result": "error", "details": "Error creating new repository."})
	}

	return c.JSON(http.StatusCreated, map[string]string{"result": "created", "details": "repository sucessfully created."})
}
