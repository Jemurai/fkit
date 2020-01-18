package utils

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
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
	json.Unmarshal(bytes, &findings)
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
