package evt

import (
	"strings"

	"golang.org/x/net/idna"
)

// Parses and returns second level domain
func parsedDomain(domain string) string {
	lowercaseDomain := strings.ToLower(domain)
	parts := strings.Split(lowercaseDomain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return lowercaseDomain
}

// Converts any internationalized domain names to ASCII
// reference: https://en.wikipedia.org/wiki/Punycode
func domainToASCII(domain string) string {
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return asciiDomain

}
