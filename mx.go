package evt

import "net"

// Detail about the Mx host
type Mx struct {
	HasMXRecord bool      // Whether has 1 or more MX record
	Records     []*net.MX // Represent DNS MX records
}

// Return the DNS MX records for the given domain name sorted by preference
func (v *Verifier) CheckMX(domain string) (*Mx, error) {
	domain = domainToASCII(domain)
	mx, err := net.LookupMX(domain)
	if err != nil {
		return nil, ParseSMTPError(err)
	}
	return &Mx{
		HasMXRecord: len(mx) > 0,
		Records:     mx,
	}, nil
}
