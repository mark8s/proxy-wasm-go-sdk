package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tidwall/gjson"
	"regexp"
	"strings"
)

func PhoneNumberDesensitize(body string) string {
	phonePat := ".*([^0-9]{1})(13|14|15|17|18|19)(\\d{9})([^0-9]{1}).*"
	replacePat := ".*(\\d{3})(\\d{4})(\\d{4}).*"
	phoneRegex := regexp.MustCompile(phonePat)
	replaceRegex := regexp.MustCompile(replacePat)
	for {
		subMatch := phoneRegex.FindStringSubmatch(body)
		if len(subMatch) != 0 {
			phoneNumber := subMatch[2] + subMatch[3]
			allString := replaceRegex.ReplaceAllString(phoneNumber, "$1****$3")
			body = strings.ReplaceAll(body, phoneNumber, allString)
		} else {
			break
		}
	}
	return body
}

func IdCardDesensitize(body string) string {
	idCardPat := "(([1-6]\\d{5})(19\\d{2}|20\\d{2})(0[1-9]|1[012])(0[1-9]|[12]\\d|3[01])(\\d{3}[\\dxX]))"
	replacePat := "(\\d{6})(\\d{8})(\\w{4})"
	idCardRegex := regexp.MustCompile(idCardPat)
	replaceRegex := regexp.MustCompile(replacePat)
	for {
		subMatch := idCardRegex.FindStringSubmatch(body)
		if len(subMatch) != 0 {
			allString := replaceRegex.ReplaceAllString(subMatch[0], "$1********$3")
			body = strings.ReplaceAll(body, subMatch[0], allString)
		} else {
			break
		}
	}
	return body
}

func postCodeDesensitize(body string) string {
	postCodePat := "^[0-9]\\d{5}$"
	replacePat := "(\\d{2})(\\d{2})(\\d{2})"
	postCodeRegex := regexp.MustCompile(postCodePat)
	replaceRegex := regexp.MustCompile(replacePat)
	for {
		subMatch := postCodeRegex.FindStringSubmatch(body)
		if len(subMatch) != 0 {
			allString := replaceRegex.ReplaceAllString(subMatch[0], "**$2$3")
			body = strings.ReplaceAll(body, subMatch[0], allString)
		} else {
			break
		}
	}
	return body
}

func isContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func validatePayload(body []byte) bool {
	if !gjson.ValidBytes(body) {
		proxywasm.LogErrorf("body is not a valid json: %q", string(body))
		return false
	}
	return true
}
