package analyze

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bizibabe/wappaGo/technologies"
	"github.com/chromedp/chromedp"
)

func (a *Analyze) analyze_js_main(technoName string, key string) {
	for js, _ := range a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{}) {
		// Convert the js expression to the window-based format
		jsExpression := a.convertToWindowExpression(js)
		if a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[js] != "" { // just check if existe & match regex
			a.analyze_js_valued(fmt.Sprintf("%v", a.ResultGlobal[technoName].(map[string]interface{})[key].(map[string]interface{})[js]), jsExpression, technoName)
		} else { // just check if existe
			a.analyze_js_exist(jsExpression, technoName)
		}
	}
}

func (a *Analyze) analyze_js_valued(regexStr string, js string, technoName string) {
	regex := strings.Split(regexStr, "\\;")
	var res interface{}
	if regex[0] != "" {
		chromedp.Evaluate("(()=>{return "+js+".match(/"+regex[0]+"/gm)[0]})()", &res).Do(a.Ctx)
	} else {
		chromedp.Evaluate("(()=>{return (typeof "+js+" !== 'undefined' ? true : false)})()", &res).Do(a.Ctx)
	}
	if res != nil && res != false {
		technoTemp := a.NewTechno(technoName)
		if (len(regex) > 1 && strings.HasPrefix(regex[1], "confidence")) || (len(regex) > 2 && strings.HasPrefix(regex[2], "confidence")) {
			if len(regex) > 1 && strings.HasPrefix(regex[1], "confidence") {
				technoTemp.Confidence = strings.Split(regex[1], ":")[1]
			}
			if len(regex) > 2 && strings.HasPrefix(regex[2], "confidence") {
				technoTemp.Confidence = strings.Split(regex[1], ":")[1]
			}
		}
		technoTemp.Version = ""
		if (len(regex) > 1 && strings.HasPrefix(regex[1], "version")) || (len(regex) > 2 && strings.HasPrefix(regex[2], "version")) {
			if len(regex) > 1 && strings.HasPrefix(regex[1], "version") {
				technoTemp.Version = fmt.Sprintf("%v", res)
			}
			if len(regex) > 2 && strings.HasPrefix(regex[2], "version") {
				technoTemp.Version = fmt.Sprintf("%v", res)
			}
		}
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}

func (a *Analyze) analyze_js_exist(js string, technoName string) {
	var res interface{}
	chromedp.Evaluate("(()=>{ return (typeof "+js+" !== 'undefined' ? true : false)})()", &res).Do(a.Ctx)
	if res == true {
		technoTemp := a.NewTechno(technoName)
		a.Technos = append(a.Technos, technoTemp)
		a.Technos = technologies.CheckRequired(technoTemp.Name, a.ResultGlobal, a.Technos)
	}
}

// convertToWindowExpression converts a JavaScript property path into a window-based format
func (a *Analyze) convertToWindowExpression(jsPath string) string {
	// Split the path by dots
	parts := strings.Split(jsPath, ".")
	// Start building the expression with window
	var expression strings.Builder
	expression.WriteString("window")
	for _, part := range parts {
		// Check if the part is an array index (numeric)
		if matched, _ := regexp.MatchString(`^\d+$`, part); matched {
			expression.WriteString(fmt.Sprintf("[%s]", part))
		} else {
			expression.WriteString(fmt.Sprintf("['%s']", part))
		}
	}

	return expression.String()
}
