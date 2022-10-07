package evt

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

const (
	defaultFromEmail = "user@example.org"
	defaultHelloName = "localhost"
)

// Creates a new email verifier
func NewVerifier() *Verifier {
	return &Verifier{
		fromEmail: defaultFromEmail,
		helloName: defaultHelloName,
	}
}
