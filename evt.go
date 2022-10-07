package evt

import "time"

const (
	emailRegexString             = "^(?:(?:(?:(?:[a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(?:\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|(?:(?:\\x22)(?:(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(?:\\x20|\\x09)+)?(?:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(\\x20|\\x09)+)?(?:\\x22))))@(?:(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	defaultFromEmail             = "user@example.org"
	defaultHelloName             = "localhost"
	smtpTimeout                  = 30 * time.Second
	smtpPort                     = ":25"
	reachableYes                 = "yes"
	reachableNo                  = "no"
	reachableUnknown             = "unknown"
	alphanumeric                 = "abcdefghijklmnopqrstuvwxyz0123456789"
	gravatarBaseUrl              = "https://www.gravatar.com/avatar/"
	gravatarDefaultMd5           = "d5fe5cbcc31cff5f8ac010db72eb000c"
	domainThreshold      float32 = 0.82
	secondLevelThreshold float32 = 0.82
	topLevelThreshold    float32 = 0.6
)

// Email verifier
// Create one by calling NewVerifier
type Verifier struct {
	smtpCheckEnabled     bool      // SMTP check
	domainSuggestEnabled bool      // Whether suggest a most similar correct domain
	gravatarCheckEnabled bool      // Gravatar check
	fromEmail            string    // Name to use in the EHLO (SMTP command. Defaults to "user@example.com")
	helloName            string    // Email to use in the MAIL FROM (SMTP command. Defaults to `localhost`)
	schedule             *schedule // Represents a job schedule
	proxyURI             string    // Whether to use a SOCKS5 proxy server
}

// Result of Email Verification
type Result struct {
	Email        string    `json:"email"`          // Passed email address
	Reachable    string    `json:"reachable"`      // Enumeration to describe whether the recipient's address is real
	Syntax       Syntax    `json:"syntax"`         // Details about the email address syntax
	SMTP         *SMTP     `json:"smtp"`           // Details about the SMTP response of the email
	Gravatar     *Gravatar `json:"gravatar"`       // Whether there is a gravatar for email
	Suggestion   string    `json:"suggestion"`     // Suggesting a domain when the domain is misspelled
	Disposable   bool      `json:"disposable"`     // Disposable email address
	RoleAccount  bool      `json:"role_account"`   // Is the account role-based
	Free         bool      `json:"free"`           // Is domain a free email domain
	HasMxRecords bool      `json:"has_mx_records"` // Whether MX-Records for the domain
}

// Creates a new email verifier
func NewVerifier() *Verifier {
	return &Verifier{
		fromEmail: defaultFromEmail,
		helloName: defaultHelloName,
	}
}

func (v *Verifier) calculateReachable(s *SMTP) string {
	if !v.smtpCheckEnabled {
		return reachableUnknown
	}
	if s.Deliverable {
		return reachableYes
	}
	if s.CatchAll {
		return reachableUnknown
	}
	return reachableNo
}
