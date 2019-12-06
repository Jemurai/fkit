package finding

import (
	"fmt"
	"strings"
	"time"
)

// Finding is a security related issue, item or todo that is intended
// to be used for standardizing such output across tools.
type Finding struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Detail      string    `json:"detail"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	Fingerprint string    `json:"fingerprint"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Location    string    `json:"location"`
	Cvss        float64   `json:"cvss"`
	References  []string  `json:"references"`
	Cwes        []string  `json:"cwes"`
	Tags        []string  `json:"tags"`
}

// GetDetailString returns a text version of a finding
// for use in a submitted issue
func GetDetailString(finding Finding) string {
	var sb strings.Builder
	sb.WriteString("Name: ")
	sb.WriteString(finding.Name)
	sb.WriteString("\nDescription:")
	sb.WriteString(finding.Description)
	sb.WriteString("\nDetail:")
	sb.WriteString(finding.Detail)
	sb.WriteString("\nSeverity:")
	sb.WriteString(finding.Severity)
	sb.WriteString("\nConfidence:")
	sb.WriteString(finding.Confidence)
	sb.WriteString("\nTimestamp:")
	stamp := fmt.Sprint(finding.Timestamp)
	sb.WriteString(stamp)
	sb.WriteString("\nSource:")
	sb.WriteString(finding.Source)
	sb.WriteString("\nLocation:")
	sb.WriteString(finding.Location)
	return sb.String()
}
