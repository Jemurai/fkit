// Copyright © 2019 Matt Konda <mkonda@jemurai.com>
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
	"fmt"
	"time"

	"github.com/jemurai/fkit/finding"
	"github.com/jemurai/fkit/utils"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newCmd represents the share command
var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new finding",
	Long: `Create a new finding.
	`,

	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		log.Debug("New finding command")
		f := buildFindingFromOptions(cmd)
		fjson, _ := json.MarshalIndent(f, "", " ")
		fmt.Printf("[%s]", fjson)
		log.Debugf("Finding %s", fjson)
		utils.Timing(start, "Elasped time: %f")
	},
}

func buildFindingFromOptions(cmd *cobra.Command) finding.Finding {

	finding := finding.Finding{
		Name:        viper.GetString("name"),
		Description: viper.GetString("description"),
		Detail:      viper.GetString("detail"),
		Severity:    viper.GetString("severity"),
		Confidence:  viper.GetString("confidence"),
		Fingerprint: viper.GetString("fingerprint"),
		Timestamp:   time.Now(),
		Source:      viper.GetString("source"),
		Location:    viper.GetString("location"),
		Cvss:        viper.GetFloat64("cvss"),
		//		References: []string,
		//		Cwes: []string,
		//		Tags: []string,
	}
	return finding
}

func init() {
	rootCmd.AddCommand(newCmd)

	newCmd.PersistentFlags().String("name", "", "The name of the finding.")
	newCmd.MarkFlagRequired("name")
	viper.BindPFlag("name", newCmd.PersistentFlags().Lookup("name"))

	newCmd.PersistentFlags().String("description", "", "The description of the finding.")
	newCmd.MarkFlagRequired("description")
	viper.BindPFlag("description", newCmd.PersistentFlags().Lookup("description"))

	newCmd.PersistentFlags().String("detail", "", "The detail of the finding.")
	newCmd.MarkFlagRequired("detail")
	viper.BindPFlag("detail", newCmd.PersistentFlags().Lookup("detail"))

	newCmd.PersistentFlags().String("severity", "", "The severity of the finding.")
	// newCmd.MarkFlagRequired("severity")
	viper.BindPFlag("severity", newCmd.PersistentFlags().Lookup("severity"))

	newCmd.PersistentFlags().String("confidence", "", "The confidence of the finding.")
	// newCmd.MarkFlagRequired("confidence")
	viper.BindPFlag("confidence", newCmd.PersistentFlags().Lookup("confidence"))

	newCmd.PersistentFlags().String("fingerprint", "", "The fingerprint of the finding.")
	newCmd.MarkFlagRequired("fingerprint")
	viper.BindPFlag("fingerprint", newCmd.PersistentFlags().Lookup("fingerprint"))

	newCmd.PersistentFlags().String("source", "", "The source of the finding.")
	newCmd.MarkFlagRequired("source")
	viper.BindPFlag("source", newCmd.PersistentFlags().Lookup("source"))

	newCmd.PersistentFlags().String("location", "", "The location of the finding.")
	newCmd.MarkFlagRequired("location")
	viper.BindPFlag("location", newCmd.PersistentFlags().Lookup("location"))

	newCmd.PersistentFlags().String("cvss", "", "The cvss of the finding.")
	// newCmd.MarkFlagRequired("cvss")
	viper.BindPFlag("cvss", newCmd.PersistentFlags().Lookup("cvss"))

	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)
}
