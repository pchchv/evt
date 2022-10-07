package evt

// Stores all information for SMTP verification lookup
type SMTP struct {
	HostExists  bool `json:"host_exists"` // Is the host exists
	FullInbox   bool `json:"full_inbox"`  // Is the email account's inbox full
	CatchAll    bool `json:"catch_all"`   // Does the domain have a catch-all email address
	Deliverable bool `json:"deliverable"` // Can email the email server
	Disabled    bool `json:"disabled"`    // Is the email blocked or disabled by the provider
}
