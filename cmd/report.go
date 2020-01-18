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
	"context"
	"fmt"
	"time"

	"github.com/jemurai/fkit/finding"

	"github.com/google/go-github/github"

	"github.com/jemurai/fkit/utils"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// reportCmd represents the share command
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Report the findings in a file to ... destinations",
	Long: `Create a github issues or other records for the findings in a file.
	`,

	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		log.Debug("Report findings command")
		file := viper.GetString("file")
		token := viper.GetString("github-token")
		repo := viper.GetString("github-repo")
		owner := viper.GetString("github-owner")

		f := utils.BuildFindingsFromFile(file)

		if token != "" {
			client := utils.GetGithubClient(token)
			ctx := context.Background()

			for i := 0; i < len(f); i++ {
				title := f[i].Name + f[i].Location
				detail := finding.GetDetailString(f[i])
				issue := &github.IssueRequest{
					Title: &title,
					Body:  &detail,
				}
				_, _, err := client.Issues.Create(ctx, owner, repo, issue)
				if err != nil {
					fmt.Printf("Error creating issue: %v", err)
				}
			}
		}
		utils.Timing(start, "Elasped time: %f")
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.PersistentFlags().String("file", "", "The file of findings to read.")
	reportCmd.MarkFlagRequired("file")
	viper.BindPFlag("file", reportCmd.PersistentFlags().Lookup("file"))

	reportCmd.PersistentFlags().String("github-token", "", "The token to use to connect to Github.")
	viper.BindPFlag("github-token", reportCmd.PersistentFlags().Lookup("github-token"))
	reportCmd.PersistentFlags().String("github-repo", "", "The repo to report issues to.")
	viper.BindPFlag("github-repo", reportCmd.PersistentFlags().Lookup("github-repo"))
	reportCmd.PersistentFlags().String("github-owner", "", "The owner to report issues to.")
	viper.BindPFlag("github-owner", reportCmd.PersistentFlags().Lookup("github-owner"))

	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)

}
