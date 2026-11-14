package parser

import (
	"encoding/json"
	"errors"
	"fmt"

	"onesocks/internal/domain"
)

func parseJSON(data []byte) (domain.ParseResult, error) {
	var result domain.ParseResult
	resolverReplacements := 0
	var entries []json.RawMessage
	if data[0] == '[' {
		if json.Unmarshal(data, &entries) != nil {
			return result, errors.New("invalid subscription JSON")
		}
	} else {
		var doc map[string]json.RawMessage
		if json.Unmarshal(data, &doc) != nil {
			return result, errors.New("invalid subscription JSON")
		}
		if _, ok := doc["proxies"]; ok {
			return parseClash(data)
		}
		if raw, ok := doc["outbounds"]; ok {
			if json.Unmarshal(raw, &entries) != nil {
				return result, errors.New("invalid outbounds list")
			}
		} else if _, ok := doc["type"]; ok {
			entries = []json.RawMessage{data}
		} else {
			return result, errors.New("JSON has no outbounds")
		}
	}
	for i, entry := range entries {
		var obj map[string]any
		var n domain.NodeSpec
		err := json.Unmarshal(entry, &obj)
		if err != nil {
			err = errors.New("invalid outbound object")
		} else {
			name := text(obj["tag"])
			delete(obj, "tag")
			delete(obj, "name")
			adapted := false
			if supported[text(obj["type"])] {
				adapted = adaptDomainResolver(obj)
			}
			n, err = makeNode(name, obj)
			if err == nil && adapted {
				resolverReplacements++
			}
		}
		appendNode(&result, n, err, i)
	}
	if resolverReplacements > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("domain_resolver references replaced with OneSocks bootstrap for %d nodes; source DNS and routing configuration were not imported", resolverReplacements))
	}
	return finish(result)
}

// Source DNS tags do not exist in the independent OneSocks runtime. Retain
// policy fields and let sing-box decode them after replacing the reference.
func adaptDomainResolver(obj map[string]any) bool {
	switch resolver := obj["domain_resolver"].(type) {
	case string:
		obj["domain_resolver"] = "bootstrap"
		return resolver != "bootstrap"
	case map[string]any:
		previous := resolver["server"]
		resolver["server"] = "bootstrap"
		return previous != "bootstrap"
	default:
		return false
	}
}
