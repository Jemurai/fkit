package utils

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/google/go-github/github"
	"github.com/jemurai/fkit/finding"
	"golang.org/x/oauth2"

	log "github.com/sirupsen/logrus"
)

// Timing calculates timing since a start time and
// outputs a message with the detail of timing.
func Timing(start time.Time, message string) time.Time {
	current := time.Now()
	elapsed := current.Sub(start)
	log.Debugf(message, elapsed.Seconds())
	return current
}

// GetGithubClient gets a client to work with
func GetGithubClient(token string) *github.Client {
	if token == "" {
		log.Info("Warning: empty token so searching public.")
		githubClient := github.NewClient(nil)
		return githubClient
	}
	// If the token is defined, get an OAuth client.
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	oauth2Client := oauth2.NewClient(context.Background(), ts)
	githubClient := github.NewClient(oauth2Client)
	return githubClient
}

// BuildFindingsFromFile read a json file of Findings and build an array
// of findings that can be used for further processing.
func BuildFindingsFromFile(file string) []finding.Finding {
	var findings []finding.Finding
	rfile, err := os.Open(file)
	if err != nil {
		log.Error(err)
	}
	bytes, err := ioutil.ReadAll(rfile)
	if err != nil {
		log.Error(err)
	}
	err = json.Unmarshal(bytes, &findings)
	if err != nil {
		log.Error(err)
	}
	return findings
}

// CompareFiles findings in files, wrapping Compare
func CompareFiles(fromfile string, tofile string) []finding.Finding {
	log.Debugf("Doing compare with %s and %s findings", fromfile, tofile)
	oldFindings := BuildFindingsFromFile(fromfile)
	newFindings := BuildFindingsFromFile(tofile)
	return Compare(oldFindings, newFindings)
}

// CompareFileAndArray wraps Compare
func CompareFileAndArray(fromfile string, newFindings []finding.Finding) []finding.Finding {
	log.Debugf("Doing compare with %s and %s findings", fromfile)
	oldFindings := BuildFindingsFromFile(fromfile)
	return Compare(oldFindings, newFindings)
}

// Compare Two Arrays
func Compare(oldFindings []finding.Finding, findings []finding.Finding) []finding.Finding {
	log.Debugf("Old findings: count %v  New findings:  %v", len(oldFindings), len(findings))
	var added []finding.Finding
	var fixed []finding.Finding
	found := false

	// Do diff. Start with fixed.
	for i := 0; i < len(oldFindings); i++ {
		found = false
		for j := 0; j < len(findings); j++ {
			if oldFindings[i].Fingerprint == findings[j].Fingerprint {
				found = true
			}
		}
		if !found {
			fixed = append(fixed, oldFindings[i])
		}
	}

	// Now look for new
	for i := 0; i < len(findings); i++ {
		found = false
		for j := 0; j < len(oldFindings); j++ {
			if findings[i].Fingerprint == oldFindings[j].Fingerprint {
				found = true
			}
		}
		if !found {
			added = append(added, findings[i])
		}
	}
	log.Debugf("\n\nSummary:\n\tIssues Fixed: %v\n\tNew Issues: %v", len(fixed), len(added))
	return added
}

// BuildFindingsFromOWASPDepCheckFile read a json file of Findings and build an array
// of findings that can be used for further processing.
func BuildFindingsFromOWASPDepCheckFile(file string) []finding.Finding {
	var findings []finding.Finding
	var dcreport OWASPDepCheckReport

	rfile, err := os.Open(file)
	if err != nil {
		log.Error(err)
	}
	bytes, err := ioutil.ReadAll(rfile)
	if err != nil {
		log.Error(err)
	}
	// TODO:  Remove the junk at the end of the JSON file;
	// 		"id" : "pkg:maven/commons-io/commons-io@2.6",
	//  	"confidence" : "HIGH",
	//  	"url" : "https://ossindex.sonatype.org/component/pkg:maven/commons-io/commons-io@2.6?utm_source=dependency-check&utm_medium=integration&utm_content=6.1.1"
	//		} ]
	//	} ]
	//	2021-02-27T16:24:51.545685284Z stdout P }

	var bracket byte = ']'
	var curly byte = '}'
	idx := len(bytes)
	bidx := 0
	log.Debugf("Length %s", idx)
	for {
		idx = idx - 1
		if idx > 0 && bytes[idx] == bracket { // Walk back to the ]
			bidx = idx
			break
		}
	}
	log.Debugf("Returning bytes 0-%s with the last chunk being %s", bidx, string(bytes[bidx-50:bidx]))
	bytes = bytes[:bidx]
	bytes = append(bytes, bracket)
	bytes = append(bytes, curly) // Add back the }

	err = json.Unmarshal(bytes, &dcreport)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("OWASP Report summary for schema version %s with %v dependencies", dcreport.ReportSchema, len(dcreport.Dependencies))
	num := 0

	for i := 0; i < len(dcreport.Dependencies); i++ {
		dep := dcreport.Dependencies[i]

		// Process []vulnerabilities
		for j := 0; j < len(dep.Findings); j++ {
			vuln := dep.Findings[j]
			var refs []string
			for k := 0; k < len(vuln.References); k++ {
				refs = append(refs, vuln.References[k].URL)
			}
			finding := finding.Finding{
				Name:        vuln.Name,
				Description: dep.Name,
				Detail:      vuln.Description,
				Severity:    vuln.Severity,
				//Confidence:  vuln.Confidence,
				//Fingerprint: viper.GetString("fingerprint"),
				Timestamp:  time.Now(),
				Source:     vuln.Source,
				Location:   dep.Path,
				Cvss:       vuln.Score2.Score,
				References: refs,
				Cwes:       vuln.CWES,
				//Tags:        viper.GetStringSlice("tag"),
			}
			if vuln.Name != "" {
				num++
				findings = append(findings, finding)
			}
		}

		// Process []vulnerabilityIds
		for j := 0; j < len(dep.FindingIds); j++ {
			vuln := dep.FindingIds[j]
			var refs []string
			finding := finding.Finding{
				Name:        vuln.Name,
				Description: dep.Name,
				Detail:      dep.Description,
				//Severity:    vuln.Severity,
				Confidence: vuln.Confidence,
				//Fingerprint: viper.GetString("fingerprint"),
				Timestamp: time.Now(),
				Source:    "OWASP Dependency Check",
				Location:  dep.Path,
				//Cvss:       vuln.Score2.Score,
				References: append(refs, vuln.URL),
				//Cwes:       vuln.CWES,
				//Tags:        viper.GetStringSlice("tag"),
			}
			if vuln.URL != "" {
				num++
				findings = append(findings, finding)
			}
		}
	}
	log.Debugf("OWASP Dependency Check found %v vulns", num)

	return findings
}

func ToCSV(findings []finding.Finding) {
	writer := csv.NewWriter(os.Stdout)
	err := writer.Write([]string{"Name", "Description", "Detail", "Severity", "Confidence", "Timestamp", "Source", "Location", "CVSS", "References"})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	for _, f := range findings {
		reference := ""
		for r := 0; r < len(f.References); r++ {
			reference = reference + f.References[r]
			if r < len(f.References)-1 {
				reference = reference + ", "
			}
		}
		err = writer.Write([]string{f.Name, f.Description, f.Detail, f.Severity, f.Confidence, f.Timestamp.String(), f.Source, f.Location, strconv.FormatFloat(f.Cvss, 'f', -1, 64), reference})
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
	}
	writer.Flush()
}
