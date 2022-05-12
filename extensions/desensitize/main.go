package main

import (
	"bytes"
	"fmt"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

// Override types.DefaultVMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext
	configuration pluginConfiguration
}

type pluginConfiguration struct {
	// desensitizeTypes support values includes honeNumber/idCard
	globals []string
	customs []string
}

// Override types.DefaultPluginContext.
func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	proxywasm.LogInfof("新的一次请求")
	return &responseContext{contextID: contextID, globals: ctx.configuration.globals, customs: ctx.configuration.customs}
}

type responseContext struct {
	contextID uint32
	types.DefaultHttpContext
	globals []string
	customs []string
}

// Override types.DefaultPluginContext.
func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil && err != types.ErrorStatusNotFound {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	config, err := parsePluginConfiguration(data)
	if err != nil {
		proxywasm.LogCriticalf("error parsing plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	ctx.configuration = config
	return types.OnPluginStartStatusOK
}

// parsePluginConfiguration parses the json plugin confiuration data and returns pluginConfiguration.
// Note that this parses the json data by gjson, since TinyGo doesn't support encoding/json.
// You can also try https://github.com/mailru/easyjson, which supports decoding to a struct.
func parsePluginConfiguration(data []byte) (pluginConfiguration, error) {

	if len(data) == 0 {
		return pluginConfiguration{}, nil
	}
	config := &pluginConfiguration{}
	if !gjson.ValidBytes(data) {
		return pluginConfiguration{}, fmt.Errorf("the plugin configuration is not a valid json: %q", string(data))
	}

	jsonData := gjson.ParseBytes(data)
	globals := jsonData.Get("globals").Array()
	if len(globals) != 0 {
		for _, globalFields := range globals {
			config.globals = append(config.globals, globalFields.Str)
		}
	}

	customs := jsonData.Get("customs").Array()
	if len(customs) != 0 {
		for _, custom := range customs {
			config.customs = append(config.customs, custom.Str)
		}
	}

	return *config, nil
}

func (r *responseContext) OnHttpResponseBody(bodySize int, endOfStream bool) types.Action {
	if !endOfStream {
		// OnHttpRequestBody may be called each time a part of the body is received.
		// Wait until we see the entire body to replace.
		return types.ActionPause
	}

	bodyByte, err := proxywasm.GetHttpResponseBody(0, bodySize)
	if err != nil {
		return 0
	}
	if err != nil {
		proxywasm.LogErrorf("failed to get response body: %v", err)
		return types.ActionContinue
	}

	isJsonData := validatePayload(bodyByte)
	if !isJsonData {
		return types.ActionPause
	}

	body := string(bodyByte)
	proxywasm.LogInfof("Response Body: %s", body)

	enablePhoneNumber := false
	enableIdCard := false
	if len(r.globals) != 0 {
		enablePhoneNumber = isContain(r.globals, "PhoneNumber")
		enableIdCard = isContain(r.globals, "IdCard")
	}
	if enablePhoneNumber {
		body = PhoneNumberDesensitize(body)
	}
	if enableIdCard {
		body = IdCardDesensitize(body)
	}

	if len(r.customs) != 0 {
		json := gjson.Parse(body)
		for _, custom := range r.customs {
			if !validateCustomRule(custom) {
				continue
			}
			customRule := strings.Split(custom, "==")
			field := customRule[0]
			desensitizeType := strings.Split(customRule[1], "#")[0]
			rule := strings.Split(customRule[1], "#")[1]
			if json.Get(field).Exists() {
				if desensitizeType == "Mask" {
					replaceValue := maskOperator(json.Get(field).String(), rule)
					body, err = sjson.Set(body, field, replaceValue)
					if err != nil {
						return 0
					}
				}
			}
		}
	}

	proxywasm.ReplaceHttpResponseBody([]byte(body))
	return types.ActionContinue
}

// Pre、Suf、Con
func maskOperator(str, rule string) string {
	rules := strings.Split(rule, "_")

	var bt bytes.Buffer
	if rules[0] == "Pre" {
		index, err := strconv.Atoi(rules[1])
		if err != nil {
			proxywasm.LogErrorf("failed to mask data: %v", err)
			return ""
		}
		for i := 0; i < index; i++ {
			bt.WriteString("*")
		}
		bt.WriteString(str[index:])
	}

	if rules[0] == "Suf" {
		index, err := strconv.Atoi(rules[1])
		if err != nil {
			proxywasm.LogErrorf("failed to mask data: %v", err)
			return ""
		}
		i := len(str) - index
		bt.WriteString(str[:i])
		for i := len(str) - index; i < len(str); i++ {
			bt.WriteString("*")
		}
	}

	if rules[0] == "Con" {
		ruleIndex := strings.Split(rules[1], "-")
		indexLeft, err := strconv.Atoi(ruleIndex[0])
		if err != nil {
			proxywasm.LogErrorf("failed to mask data: %v", err)
			return ""
		}
		indexRight, err := strconv.Atoi(ruleIndex[1])
		if err != nil {
			proxywasm.LogErrorf("failed to mask data: %v", err)
			return ""
		}
		bt.WriteString(str[:indexLeft-1])
		for i := indexLeft; i <= indexRight; i++ {
			bt.WriteString("*")
		}
		bt.WriteString(str[indexRight:])
	}

	return bt.String()
}

func validateCustomRule(rule string) bool {
	if !strings.Contains(rule, "==") || !strings.Contains(rule, "#") || !strings.Contains(rule, "_") {
		proxywasm.LogErrorf("customs rule is not a valid format: %s", rule)
		return false
	}
	return true
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
