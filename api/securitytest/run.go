package securitytest

import (
	"sync"

	apiContext "github.com/globocom/huskyCI/api/context"
	"github.com/globocom/huskyCI/api/log"
	"github.com/globocom/huskyCI/api/types"
)

// RunAllInfo store all scans results of an Analysis
type RunAllInfo struct {
	RID            string
	Status         string
	Containers     []types.Container
	CommitAuthors  []string
	Codes          []types.Code
	FinalResult    string
	ErrorFound     error
	HuskyCIResults types.HuskyCIResults
}

const bandit = "bandit"
const brakeman = "brakeman"
const safety = "safety"
const gosec = "gosec"
const npmaudit = "npmaudit"
const yarnaudit = "yarnaudit"
const spotbugs = "spotbugs"
const gitleaks = "gitleaks"
const tfsec = "tfsec"

// Start runs both generic and language security
func (results *RunAllInfo) Start(enryScan SecTestScanInfo) error {

	results.Codes = enryScan.Codes
	errChan := make(chan error)
	waitChan := make(chan struct{})
	syncChan := make(chan struct{})

	var wg sync.WaitGroup

	defer close(errChan)
	defer results.setToAnalysis()
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := results.runGenericScans(enryScan); err != nil {
			select {
			case <-syncChan:
				return
			case errChan <- err:
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		if err := results.runLanguageScans(enryScan); err != nil {
			select {
			case <-syncChan:
				return
			case errChan <- err:
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		return nil
	case err := <-errChan:
		close(syncChan)
		results.ErrorFound = err
		return err
	}
}

func (results *RunAllInfo) runGenericScans(enryScan SecTestScanInfo) error {

	errChan := make(chan error)
	waitChan := make(chan struct{})
	syncChan := make(chan struct{})

	var wg sync.WaitGroup

	defer close(errChan)

	genericTests, err := getAllDefaultSecurityTests("Generic", "")
	if err != nil {
		return err
	}

	for genericTestIndex := range genericTests {
		wg.Add(1)
		go func(genericTest *types.SecurityTest) {
			defer wg.Done()
			newGenericScan := SecTestScanInfo{}
			newGenericScan.TimeOut = enryScan.TimeOut
			if err := newGenericScan.New(enryScan.RID, enryScan.URL, enryScan.Branch, genericTest.Name); err != nil {
				select {
				case <-syncChan:
					return
				case errChan <- err:
					return
				}
			}
			if err := newGenericScan.Start(); err != nil {
				select {
				case <-syncChan:
					return
				case errChan <- err:
					return
				}
			}
			results.Containers = append(results.Containers, newGenericScan.Container)
			if genericTest.Name == "gitauthors" {
				results.CommitAuthors = newGenericScan.CommitAuthors.Authors
			} else if genericTest.Name == "gitleaks" {
				results.setVulns(newGenericScan)
			}
		}(&genericTests[genericTestIndex])
	}

	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		return nil
	case err := <-errChan:
		close(syncChan)
		return err
	}
}

func (results *RunAllInfo) runLanguageScans(enryScan SecTestScanInfo) error {

	errChan := make(chan error)
	waitChan := make(chan struct{})
	syncChan := make(chan struct{})

	var wg sync.WaitGroup

	defer close(errChan)

	languageTests := []types.SecurityTest{}
	for _, code := range enryScan.Codes {
		codeTests, err := getAllDefaultSecurityTests("Language", code.Language)
		if err != nil {
			return err
		}
		languageTests = append(languageTests, codeTests...)
	}

	for languageTestIndex := range languageTests {
		wg.Add(1)
		go func(languageTest *types.SecurityTest) {
			defer wg.Done()
			newLanguageScan := SecTestScanInfo{}
			newLanguageScan.TimeOut = enryScan.TimeOut
			if err := newLanguageScan.New(enryScan.RID, enryScan.URL, enryScan.Branch, languageTest.Name); err != nil {
				select {
				case <-syncChan:
					return
				case errChan <- err:
					return
				}
			}
			if err := newLanguageScan.Start(); err != nil {
				results.Containers = append(results.Containers, newLanguageScan.Container)
				select {
				case <-syncChan:
					return
				case errChan <- err:
					return
				}
			}
			results.Containers = append(results.Containers, newLanguageScan.Container)
			results.setVulns(newLanguageScan)
		}(&languageTests[languageTestIndex])
	}

	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		return nil
	case err := <-errChan:
		close(syncChan)
		return err
	}
}

func (results *RunAllInfo) setVulns(securityTestScan SecTestScanInfo) {

	for _, highVuln := range securityTestScan.Vulnerabilities.HighVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns, highVuln)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns, highVuln)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns, highVuln)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns, highVuln)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns, highVuln)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns, highVuln)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns, highVuln)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns, highVuln)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.HighVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.HighVulns, highVuln)
		}
	}

	for _, mediumVuln := range securityTestScan.Vulnerabilities.MediumVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns, mediumVuln)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns, mediumVuln)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns, mediumVuln)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns, mediumVuln)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns, mediumVuln)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns, mediumVuln)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns, mediumVuln)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns, mediumVuln)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.MediumVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.MediumVulns, mediumVuln)
		}
	}

	for _, lowVuln := range securityTestScan.Vulnerabilities.LowVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns, lowVuln)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns, lowVuln)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns, lowVuln)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns, lowVuln)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns, lowVuln)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns, lowVuln)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns, lowVuln)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns, lowVuln)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.LowVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.LowVulns, lowVuln)
		}
	}

	for _, noSec := range securityTestScan.Vulnerabilities.NoSecVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.NoSecVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.NoSecVulns, noSec)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.NoSecVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.NoSecVulns, noSec)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.NoSecVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.NoSecVulns, noSec)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.NoSecVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.NoSecVulns, noSec)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.NoSecVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.NoSecVulns, noSec)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.NoSecVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.NoSecVulns, noSec)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.NoSecVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.NoSecVulns, noSec)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.NoSecVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.NoSecVulns, noSec)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.NoSecVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.NoSecVulns, noSec)
		}
	}
}

// SetAnalysisError sets error on an analysis that did not got to the setToAnalysis phase
func (results *RunAllInfo) SetAnalysisError(err error) {
	results.ErrorFound = err
	results.Status = "error running"
	results.FinalResult = "error"
}

func (results *RunAllInfo) setToAnalysis() {

	results.Status = "finished"
	results.FinalResult = "passed"

	if results.ErrorFound != nil {
		results.Status = "error running"
		results.FinalResult = "error"
		return
	}

	jsWarningFlag := false

	for _, container := range results.Containers {
		switch container.CResult {
		case "warning":
			if container.SecurityTest.Language == "JavaScript" {
				if jsWarningFlag {
					results.FinalResult = "warning"
				} else {
					jsWarningFlag = true
				}
			} else {
				results.FinalResult = "warning"
			}
		case "failed":
			results.FinalResult = "failed"
			return
		}
	}
}

func getAllDefaultSecurityTests(typeOf, language string) ([]types.SecurityTest, error) {
	securityTestQuery := map[string]interface{}{"type": typeOf, "default": true}
	if language != "" {
		securityTestQuery = map[string]interface{}{"language": language, "default": true}
	}
	securityTests, err := apiContext.APIConfiguration.DBInstance.FindAllDBSecurityTest(securityTestQuery)
	if err != nil {
		if err.Error() == "No data found" {
			return securityTests, nil
		}
		log.Error("getAllDefaultSecurityTests", "SECURITYTEST", 2009, err)
		return securityTests, err
	}
	return securityTests, nil
}
