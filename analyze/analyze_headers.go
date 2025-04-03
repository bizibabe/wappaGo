package analyze

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bizibabe/wappaGo/technologies"
)

func (a *Analyze) analyze_headers_main(technoName string, key string) {
	// Vérifiez que ResultGlobal contient technoName et que c'est bien une map[string]interface{}
	resultData, ok := a.ResultGlobal[technoName].(map[string]interface{})
	if !ok || resultData == nil || resultData[key] == nil {
		return
	}

	// Vérifiez que resultData[key] est une map[string]interface{}
	headerData, ok := resultData[key].(map[string]interface{})
	if !ok || headerData == nil {
		return
	}

	// Parcourir les en-têtes attendus
	for header := range headerData {
		for headerName := range a.Resp.Headers {
			if strings.ToLower(header) == strings.ToLower(headerName) {
				headerValue := headerData[header]

				// Vérifiez si headerValue est nil
				if headerValue == nil {
					continue // Passez à l'itération suivante si headerValue est nil
				}

				// Construisez et vérifiez la regex
				regex := strings.Split(fmt.Sprintf("%v", headerValue), "\\;")
				pattern := "(?i)" + regex[0]
				findregex, _ := regexp.MatchString(pattern, a.Resp.Headers[headerName][0])

				// Affichez les valeurs pour le débogage
				// fmt.Println("Regex Pattern: ", pattern)
				// fmt.Println("Header Value: ", a.Resp.Headers[headerName][0])
				// fmt.Println("Find: ", findregex, " | Technoname:  ", technoName, " | HeaderName:   ", headerName)

				if findregex {
					technoTemp := a.NewTechno(technoName)
					compiledregex := regexp.MustCompile(pattern)
					regexGroup := compiledregex.FindAllStringSubmatch(a.Resp.Headers[headerName][0], -1)

					technoTemp.Version = ""
					if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
						versionGrp := strings.Split(regex[1], "\\")
						if len(versionGrp) > 1 {
							offset, _ := strconv.Atoi(versionGrp[1])
							if len(regexGroup) > 0 && len(regexGroup[0]) > offset {
								technoTemp.Version = regexGroup[0][offset]
							}
						}
					}
					a.Technos = append(a.Technos, technoTemp)
					a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
				}
			}
		}
	}
}
