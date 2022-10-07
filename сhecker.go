package evt

import (
	"strings"
	"sync"
)

var (
	disposableSyncDomains sync.Map // Concurrent safe map to store disposable domains data
)

// Checks if the domain is free
func (v *Verifier) IsFreeDomain(domain string) bool {
	return freeDomains[domain]
}

// Checks if username is a role-based account
func (v *Verifier) IsRoleAccount(username string) bool {
	return roleAccounts[strings.ToLower(username)]
}

// Checks if the domain is disposable
func (v *Verifier) IsDisposable(domain string) bool {
	domain = domainToASCII(domain)
	d := parsedDomain(domain)
	_, found := disposableSyncDomains.Load(d)
	return found
}
