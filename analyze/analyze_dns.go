package analyze

import (
	"fmt"
	"regexp"

	"github.com/bizibabe/wappaGo/technologies"
)

// analyze_dns_main performs DNS analysis based on provided keys and values.
func (a *Analyze) analyze_dns_main(technoName string, key string) {
	technoData, exists := a.ResultGlobal[technoName]
	if !exists {
		fmt.Printf("TechnoName %v not found in ResultGlobal\n", technoName)
		return
	}

	technoMap, ok := technoData.(map[string]interface{})
	if !ok {
		fmt.Printf("Invalid structure for technoName: %v\n", technoName)
		return
	}

	value, exists := technoMap[key]
	if !exists {
		fmt.Printf("Key %v not found for technoName %v\n", key, technoName)
		return
	}

	keyData, ok := value.(map[string]interface{})
	if !ok {
		fmt.Printf("Invalid key structure for key: %v\n", key)
		return
	}

	for key, value := range keyData {
		var resultDNS []string
		switch key {
		case "TXT":
			resultDNS = a.DnsData.TXT
		case "SOA":
			resultDNS = a.DnsData.SOA
		case "NS":
			resultDNS = a.DnsData.NS
		case "CNAME":
			resultDNS = a.DnsData.CNAME
		case "MX":
			resultDNS = a.DnsData.MX
		default:
			fmt.Printf("Unknown DNS type: %v\n", key)
			continue
		}

		switch v := value.(type) {
		case string:
			if a.analyze_dns_regex(v, resultDNS) {
				technoTemp := a.NewTechno(technoName)
				a.Technos = append(a.Technos, technoTemp)
				a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
			}
		case []interface{}:
			for _, regex := range v {
				if regexStr, ok := regex.(string); ok {
					if a.analyze_dns_regex(regexStr, resultDNS) {
						technoTemp := a.NewTechno(technoName)
						a.Technos = append(a.Technos, technoTemp)
						a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
					}
				} else {
					fmt.Printf("Invalid regex type: %v\n", regex)
				}
			}
		default:
			fmt.Printf("Unexpected value type: %T\n", value)
		}
	}
}

// analyze_dns_regex performs regex matching on DNS results.
func (a *Analyze) analyze_dns_regex(regex string, resultsDNS []string) bool {
	for _, resultDNS := range resultsDNS {
		// Match the regex pattern against the DNS result.
		findregex, err := regexp.MatchString("(?i)"+regex, resultDNS)
		if err != nil {
			fmt.Printf("Regex error: %v\n", err)
			continue
		}
		if findregex {
			return true
		}
	}
	return false
}
