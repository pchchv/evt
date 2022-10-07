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
