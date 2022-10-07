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
	disposableDataURL            = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.json"
	gravatarBaseUrl              = "https://www.gravatar.com/avatar/"
	gravatarDefaultMd5           = "d5fe5cbcc31cff5f8ac010db72eb000c"
	domainThreshold      float32 = 0.82
	secondLevelThreshold float32 = 0.82
	topLevelThreshold    float32 = 0.6
)

// Additional list of disposable domains set via users of this library
var additionalDisposableDomains map[string]bool = map[string]bool{}

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

// Loads disposable domain metadata to disposableSyncDomains which are safe for concurrent use
func init() {
	for d := range disposableDomains {
		disposableSyncDomains.Store(d, struct{}{})
	}
}

// Creates a new email verifier
func NewVerifier() *Verifier {
	return &Verifier{
		fromEmail: defaultFromEmail,
		helloName: defaultHelloName,
	}
}

// Performs address, misc, mx and smtp checks
func (v *Verifier) Verify(email string) (*Result, error) {
	ret := Result{
		Email:     email,
		Reachable: reachableUnknown,
	}
	syntax := v.ParseAddress(email)
	ret.Syntax = syntax
	if !syntax.Valid {
		return &ret, nil
	}
	ret.Free = v.IsFreeDomain(syntax.Domain)
	ret.RoleAccount = v.IsRoleAccount(syntax.Username)
	ret.Disposable = v.IsDisposable(syntax.Domain)
	// If the domain name is disposable, mx and smtp are not checked
	if ret.Disposable {
		return &ret, nil
	}
	mx, err := v.CheckMX(syntax.Domain)
	if err != nil {
		return &ret, err
	}
	ret.HasMxRecords = mx.HasMXRecord
	smtp, err := v.CheckSMTP(syntax.Domain, syntax.Username)
	if err != nil {
		return &ret, err
	}
	ret.SMTP = smtp
	ret.Reachable = v.calculateReachable(smtp)
	if v.gravatarCheckEnabled {
		gravatar, err := v.CheckGravatar(email)
		if err != nil {
			return &ret, err
		}
		ret.Gravatar = gravatar
	}
	if v.domainSuggestEnabled {
		ret.Suggestion = v.SuggestDomain(syntax.Domain)
	}
	return &ret, nil
}

// Adds additional domains as disposable domains
func (v *Verifier) AddDisposableDomains(domains []string) *Verifier {
	for _, d := range domains {
		additionalDisposableDomains[d] = true
		disposableSyncDomains.Store(d, struct{}{})
	}
	return v
}

// Enables check gravatar, we don't check gravatar by default
func (v *Verifier) EnableGravatarCheck() *Verifier {
	v.gravatarCheckEnabled = true
	return v
}

// Disables check gravatar
func (v *Verifier) DisableGravatarCheck() *Verifier {
	v.gravatarCheckEnabled = false
	return v
}

// Enables check email by smtp, for most ISPs block outgoing SMTP requests through port 25,
// to prevent spam, we don't check smtp by default
func (v *Verifier) EnableSMTPCheck() *Verifier {
	v.smtpCheckEnabled = true
	return v
}

// Disables check email by smtp
func (v *Verifier) DisableSMTPCheck() *Verifier {
	v.smtpCheckEnabled = false
	return v
}

// Will uggest a most similar correct domain when domain misspelled
func (v *Verifier) EnableDomainSuggest() *Verifier {
	v.domainSuggestEnabled = true
	return v
}

// Will not suggest anything
func (v *Verifier) DisableDomainSuggest() *Verifier {
	v.domainSuggestEnabled = false
	return v
}

// Enables update disposable domains automatically
func (v *Verifier) EnableAutoUpdateDisposable() *Verifier {
	v.stopCurrentSchedule()
	// Update disposable domains records daily
	v.schedule = newSchedule(24*time.Hour, updateDisposableDomains, disposableDataURL)
	v.schedule.start()
	return v
}

// Stops previously started schedule job
func (v *Verifier) DisableAutoUpdateDisposable() *Verifier {
	v.stopCurrentSchedule()
	return v

}

// Sets the emails to use in the `MAIL FROM:` smtp command
func (v *Verifier) FromEmail(email string) *Verifier {
	v.fromEmail = email
	return v
}

// Sets the name to use in the `EHLO:` SMTP command
func (v *Verifier) HelloName(domain string) *Verifier {
	v.helloName = domain
	return v
}

// Sets a SOCKS5 proxy to verify the email,
// proxyURI should be in the format: "socks5://user:password@127.0.0.1:1080?timeout=5s".
// The protocol could be socks5, socks4 and socks4a.
func (v *Verifier) Proxy(proxyURI string) *Verifier {
	v.proxyURI = proxyURI
	return v
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

// Stops current running schedule (if exists)
func (v *Verifier) stopCurrentSchedule() {
	if v.schedule != nil {
		v.schedule.stop()
	}
}
