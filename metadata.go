package evt

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

var (
	roleAccounts                 = getMap("roleAccounts.json")      // Map to store role-based accounts data
	disposableDomains            = getMap("disposableDomains.json") // map to store disposable domains data
	freeDomains                  = getMap("freeDomains.json")       // Map to store free domains data
	suggestionSecondLevelDomains = map[string]bool{                 // Second level domains to check misspelled domains
		"yahoo":   true,
		"hotmail": true,
		"mail":    true,
		"live":    true,
		"outlook": true,
		"gmx":     true,
	}
	suggestionTopLevelDomains = map[string]bool{ // Top level domains to check misspelled domains
		"com":    true,
		"com.au": true,
		"com.tw": true,
		"ca":     true,
		"co.nz":  true,
		"co.uk":  true,
		"de":     true,
		"fr":     true,
		"it":     true,
		"ru":     true,
		"org":    true,
		"edu":    true,
		"gov":    true,
		"jp":     true,
		"nl":     true,
		"kr":     true,
		"se":     true,
		"eu":     true,
		"ie":     true,
		"co.il":  true,
		"us":     true,
		"at":     true,
		"be":     true,
		"dk":     true,
		"hk":     true,
		"es":     true,
		"gr":     true,
		"ch":     true,
		"no":     true,
		"cz":     true,
		"in":     true,
		"net":    true,
		"net.au": true,
		"info":   true,
		"biz":    true,
		"mil":    true,
		"co.jp":  true,
		"sg":     true,
		"hu":     true,
		"uk":     true,
	}
)

func getMap(filename string) map[string]bool {
	var result map[string]bool
	jsonFile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &result)
	return result
}
