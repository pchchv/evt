package evt

import (
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(emailRegexString)

// Stores all information about an email Syntax
type Syntax struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Valid    bool   `json:"valid"`
}

// Attempts to parse an email address and return it in the form of a Syntax
func (v *Verifier) ParseAddress(email string) Syntax {
	isAddressValid := IsAddressValid(email)
	if !isAddressValid {
		return Syntax{Valid: false}
	}
	index := strings.LastIndex(email, "@")
	username := email[:index]
	domain := strings.ToLower(email[index+1:])
	return Syntax{
		Username: username,
		Domain:   domain,
		Valid:    isAddressValid,
	}
}

// Checks if email address is formatted correctly by using regex
func IsAddressValid(email string) bool {
	return emailRegex.MatchString(email)
}
