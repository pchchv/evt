package evt

import (
	"crypto/md5"
	"encoding/hex"
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

// Use md5 to encode string
func getMD5Hash(str string) (error, string) {
	h := md5.New()
	_, err := h.Write([]byte(str))
	if err != nil {
		return err, ""
	}
	return nil, hex.EncodeToString(h.Sum(nil))
}
