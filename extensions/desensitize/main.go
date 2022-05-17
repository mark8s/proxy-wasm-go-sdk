package main

import (
	"fmt"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
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

	if len(r.globals) != 0 {
		if isContain(r.globals, "PhoneNumber") {
			body = PhoneNumberDesensitize(body)
		}
		if isContain(r.globals, "IdCard") {
			body = IdCardDesensitize(body)
		}
	}

	if len(r.customs) != 0 {
		json := gjson.Parse(body)
		for _, custom := range r.customs {
			if !validateCustomRule(custom) {
				continue
			}
			var action types.Action
			var done bool
			body, action, done = r.customDesensitize(custom, json, body, err)
			if done {
				return action
			}
		}
	}

	proxywasm.ReplaceHttpResponseBody([]byte(body))
	return types.ActionContinue
}

func (r *responseContext) customDesensitize(custom string, json gjson.Result, body string, err error) (string, types.Action, bool) {
	customRule := strings.Split(custom, "==")
	field := customRule[0]
	desensitizeType := strings.Split(customRule[1], "#")[0]
	rule := strings.Split(customRule[1], "#")[1]
	if json.Get(field).Exists() {
		if desensitizeType == "Mask" {
			replaceValue := maskOperator(json.Get(field).String(), rule)
			body, err = sjson.Set(body, field, replaceValue)
			if err != nil {
				return "", 0, true
			}
		}
	}
	return body, 0, false
}
