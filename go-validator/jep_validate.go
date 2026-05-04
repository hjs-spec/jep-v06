package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func canonical(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x { return "true" }; return "false"
	case float64:
		b, _ := json.Marshal(x); return string(b)
	case string:
		b, _ := json.Marshal(x); return string(b)
	case []interface{}:
		parts := []string{}
		for _, e := range x { parts = append(parts, canonical(e)) }
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		keys := []string{}
		for k := range x { keys = append(keys, k) }
		sort.Strings(keys)
		parts := []string{}
		for _, k := range keys {
			kb, _ := json.Marshal(k)
			parts = append(parts, string(kb)+":"+canonical(x[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := json.Marshal(x); return string(b)
	}
}

func eventHash(event map[string]interface{}) string {
	sum := sha256.Sum256([]byte(canonical(event)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run jep_validate.go <event-or-vector.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil { panic(err) }
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil { panic(err) }
	event := obj
	if ev, ok := obj["event"].(map[string]interface{}); ok { event = ev }

	valid := true
	code := ""
	for _, f := range []string{"jep","verb","who","when","nonce","sig"} {
		if _, ok := event[f]; !ok { valid=false; code="ERR_MISSING_REQUIRED_FIELD" }
	}
	if event["jep"] != "1" { valid=false; code="ERR_UNSUPPORTED_JEP_VERSION" }
	if sig, ok := event["sig"].(string); ok {
		parts := strings.Split(sig, ".")
		if len(parts) != 3 || parts[1] != "" { valid=false; code="ERR_SIGNATURE_CONTAINER_INVALID" }
		if len(parts) == 3 {
			if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil { valid=false; code="ERR_SIGNATURE_CONTAINER_INVALID" }
		}
	} else { valid=false; code="ERR_SIGNATURE_CONTAINER_INVALID" }

	out := map[string]interface{}{
		"valid": valid,
		"level": 0,
		"mode": "structural",
		"profile": "jep-core-0.6",
		"event_hash": eventHash(event),
		"warnings": []interface{}{},
		"errors": []interface{}{},
	}
	if !valid {
		out["errors"] = []interface{}{map[string]interface{}{"code": code, "message": code, "level": 0, "recoverable": false}}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	if !valid { os.Exit(1) }
}
