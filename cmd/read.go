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
	"io/ioutil"
	"os"
	"time"

	"github.com/jemurai/fkit/finding"
	"github.com/jemurai/fkit/utils"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// readCmd represents the read command
var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Read findings out of a JSON file",
	Long: `Read findings.
	`,

	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		file := viper.GetString("infile")
		log.Debugf("Read finding command on %s", file)
		f := BuildFindingsFromFile(file)
		fjson, _ := json.MarshalIndent(f, "", " ")
		log.Debugf("Finding %s", fjson)
		utils.Timing(start, "Elasped time: %f")
	},
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

func init() {
	rootCmd.AddCommand(readCmd)

	readCmd.PersistentFlags().String("infile", "", "The file of findings to read.")
	readCmd.MarkFlagRequired("infile")
	viper.BindPFlag("infile", readCmd.PersistentFlags().Lookup("infile"))

	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)
}
