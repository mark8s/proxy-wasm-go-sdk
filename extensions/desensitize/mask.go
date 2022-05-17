package main

import (
	"bytes"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"strconv"
	"strings"
)

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
		if ruleIndex[1] < ruleIndex[0] {
			proxywasm.LogErrorf("Index Error, CON start index cannot < end start")
			return ""
		}

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
