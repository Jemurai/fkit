// Copyright © 2019-2020 Matt Konda <mkonda@jemurai.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"time"

	"github.com/jemurai/fkit/finding"
	"github.com/jemurai/fkit/utils"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// compareCmd represents the compare command
var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare findings across two JSON files",
	Long: `Compare findings across two JSON files.
	`,

	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		log.Debug("Compare finding command")
		fromfile := viper.GetString("fromfile")
		tofile := viper.GetString("tofile")
		f := CompareFiles(fromfile, tofile)
		fjson, _ := json.MarshalIndent(f, "", " ")
		log.Debugf("Finding %s", fjson)
		utils.Timing(start, "Elasped time: %f")
	},
}

func init() {
	rootCmd.AddCommand(compareCmd)

	compareCmd.PersistentFlags().String("fromfile", "", "The file of findings to read.")
	compareCmd.MarkFlagRequired("fromfile")
	viper.BindPFlag("fromfile", compareCmd.PersistentFlags().Lookup("fromfile"))

	compareCmd.PersistentFlags().String("tofile", "", "The file of findings to read.")
	compareCmd.MarkFlagRequired("tofile")
	viper.BindPFlag("tofile", compareCmd.PersistentFlags().Lookup("tofile"))

	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)
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
	log.Debugf("Doing compare with %s and %s findings", fromfile,)
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
