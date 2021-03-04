// Copyright © 2019-2021 Matt Konda <mkonda@jemurai.com>
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
		f := utils.CompareFiles(fromfile, tofile)
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
