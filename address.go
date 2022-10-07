package evt

// Stores all information about an email Syntax
type Syntax struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Valid    bool   `json:"valid"`
}
