// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"errors"
	"os"
	"strconv"
)

// RepositoryURL stores the repository URL of the project to be analyzed.
var RepositoryURL string

// HuskyAPI stores the address of Husky's API.
var HuskyAPI string

// RepositoryBranch stores the repository branch of the project to be analyzed.
var RepositoryBranch string

// HuskyToken is the token used to scan a repository.
var HuskyToken string

// HuskyUseTLS stores if huskyCI is to use an HTTPS connection.
var HuskyUseTLS bool

// Timeout in Seconds for huskyCI tests
var TimeOutInSeconds int

// SetConfigs sets all configuration needed to start the client.
func SetConfigs() {
	RepositoryURL = os.Getenv(`HUSKYCI_CLIENT_REPO_URL`)
	RepositoryBranch = os.Getenv(`HUSKYCI_CLIENT_REPO_BRANCH`)
	HuskyAPI = os.Getenv(`HUSKYCI_CLIENT_API_ADDR`)
	HuskyToken = os.Getenv(`HUSKYCI_CLIENT_TOKEN`)
	HuskyUseTLS = getUseTLS()
	TimeOutInSeconds, _ = strconv.Atoi(os.Getenv(`HUSKYCI_CLIENT_TESTS_TIMEOUT`))
}

// CheckEnvVars checks if all environment vars are set.
func CheckEnvVars() error {

	envVars := []string{
		"HUSKYCI_CLIENT_API_ADDR",
		"HUSKYCI_CLIENT_REPO_URL",
		"HUSKYCI_CLIENT_REPO_BRANCH",
		// "HUSKYCI_CLIENT_TOKEN", (optional for now)
		// "HUSKYCI_CLIENT_API_USE_HTTPS", (optional)
		// "HUSKYCI_CLIENT_NPM_DEP_URL", (optional)
	}

	var envIsSet bool
	var allEnvIsSet bool
	var errorString string

	env := make(map[string]string)
	allEnvIsSet = true
	for i := 0; i < len(envVars); i++ {
		env[envVars[i]], envIsSet = os.LookupEnv(envVars[i])
		if !envIsSet {
			errorString = errorString + envVars[i] + " "
			allEnvIsSet = false
		}
	}
	if !allEnvIsSet {
		return errors.New(errorString)
	}
	return nil
}

// getUseTLS returns TRUE or FALSE retrieved from an environment variable.
func getUseTLS() bool {
	option := os.Getenv("HUSKYCI_CLIENT_API_USE_HTTPS")
	if option == "true" || option == "1" || option == "TRUE" {
		return true
	}
	return false
}
