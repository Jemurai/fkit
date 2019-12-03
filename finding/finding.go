package finding

import "time"

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
