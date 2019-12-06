package utils

import (
	"context"
	"time"

	"github.com/google/go-github/github"
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
