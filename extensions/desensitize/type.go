package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	. "github.com/tidwall/gjson"
	"strconv"
	"strings"
	"time"
)

func truncation(str Result, rule string) interface{} {
	var offset int
	var err error
	if !strings.Contains(rule, "_") {
		offset, err = strconv.Atoi(rule)
		if err != nil {
			proxywasm.LogErrorf("failed to truncation data: %v", err)
			return ""
		}
	} else {
		offset, err = strconv.Atoi(strings.Split(rule, "_")[1])
		if err != nil {
			proxywasm.LogErrorf("failed to truncation data: %v", err)
			return ""
		}
	}
	var bt bytes.Buffer
	index := len(str.String()) - offset
	bt.WriteString(str.String()[:index])

	var result interface{}
	if str.Type == String {
		result = bt.String()
	} else if str.Type == Number {
		if strings.Contains(bt.String(), ".") {
			result, err = strconv.ParseFloat(bt.String(), 64)
			if err != nil {
				proxywasm.LogErrorf("failed to truncation data: %v", err)
				return ""
			}
		} else {
			result, err = strconv.Atoi(bt.String())
			if err != nil {
				proxywasm.LogErrorf("failed to truncation data: %v", err)
				return ""
			}
		}
	}
	return result
}

func enumeration(str Result) interface{} {
	var result interface{}
	if str.Type == String {
		strInt, err := strconv.Atoi(str.Str)
		if err != nil {
			proxywasm.LogErrorf("failed to enumeration data: %v", err)
			return ""
		}
		result = strconv.Itoa(time.Now().Day() * strInt)
	} else if str.Type == Number {
		if strings.Contains(str.String(), ".") {
			float, err := strconv.ParseFloat(str.String(), 64)
			if err != nil {
				proxywasm.LogErrorf("failed to enumeration data: %v", err)
				return nil
			}
			return float64(time.Now().Day()) * float
		} else {
			return int64(time.Now().Day()) * str.Int()
		}
	}
	return result
}

func shift(str Result, rule string) interface{} {
	var offset int
	var err error
	if !strings.Contains(rule, "_") {
		offset, err = strconv.Atoi(rule)
		if err != nil {
			proxywasm.LogErrorf("failed to shift data: %v", err)
			return ""
		}
	} else {
		offset, err = strconv.Atoi(strings.Split(rule, "_")[1])
		if err != nil {
			proxywasm.LogErrorf("failed to shift data: %v", err)
			return ""
		}
	}

	var bt bytes.Buffer
	for i := 0; i < offset; i++ {
		bt.WriteString("1")
	}

	var result interface{}
	if str.Type == String {
		result = bt.String() + str.String()
	} else if str.Type == Number {
		if strings.Contains(str.String(), ".") {
			c := bt.String() + str.String()
			strFloat, err := strconv.ParseFloat(c, 64)
			if err != nil {
				proxywasm.LogErrorf("failed to shift data: %v", err)
				return nil
			}
			return strFloat
		} else {
			result, err = strconv.Atoi(bt.String() + str.String())
			if err != nil {
				proxywasm.LogErrorf("failed to shift data: %v", err)
				return -1
			}
		}
	}
	return result
}

func hash(str string) string {
	s := fmt.Sprintf("%x", md5.Sum([]byte(str)))
	return s
}

// Pre、Suf、Con
func mask(str, rule string) string {
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
