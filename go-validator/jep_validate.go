package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	coreProfile      = "jep-core-0.6"
	conformanceClass = "JEP-Core-0.6 Syntax Verifier Seed"
)

var (
	digestRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*:[0-9a-f]+$`)
	uuidV4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	b64uRE   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	topLevel = map[string]bool{
		"jep": true, "verb": true, "who": true, "when": true, "what": true,
		"nonce": true, "aud": true, "ref": true, "ext": true, "ext_crit": true,
		"sig": true,
	}
)

type validationError struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Level       int    `json:"level"`
	Recoverable bool   `json:"recoverable"`
}

type validationResult struct {
	Valid            bool              `json:"valid"`
	Level            int               `json:"level"`
	Mode             string            `json:"mode"`
	Profile          string            `json:"profile"`
	ConformanceClass string            `json:"conformance_class"`
	Scopes           []string          `json:"scopes"`
	EventHash        *string           `json:"event_hash"`
	Warnings         []any             `json:"warnings"`
	Errors           []validationError `json:"errors"`
}

type fault struct {
	code    string
	message string
	level   int
}

func (f fault) Error() string { return f.message }

func fail(code, message string, level int) error {
	return fault{code: code, message: message, level: level}
}

// parseJSONUnique preserves JSON numbers and rejects duplicate object member names
// before a normal map decoder could discard them.
func parseJSONUnique(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("JSON is not valid UTF-8")
	}
	if err := validateEscapedSurrogates(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing token %v", tok)
		}
		return nil, err
	}
	if err := validateIJSON(value, "$"); err != nil {
		return nil, err
	}
	return value, nil
}

func validateEscapedSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if !inString {
			if raw[i] == '"' {
				inString = true
			}
			continue
		}
		if raw[i] == '"' {
			inString = false
			continue
		}
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return fmt.Errorf("unterminated JSON escape")
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return fmt.Errorf("short Unicode escape")
		}
		unit, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid Unicode escape")
		}
		i += 4
		r := rune(unit)
		if utf16.IsSurrogate(r) {
			if r >= 0xDC00 {
				return fmt.Errorf("unpaired low surrogate in JSON string")
			}
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return fmt.Errorf("unpaired high surrogate in JSON string")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return fmt.Errorf("unpaired high surrogate in JSON string")
			}
			i += 6
		}
	}
	return nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object member name is not a string")
				}
				if _, exists := obj[key]; exists {
					return nil, fault{code: "ERR_DUPLICATE_MEMBER", message: "duplicate JSON member: " + key, level: 0}
				}
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = value
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("unterminated object")
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, value)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("unterminated array")
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", t)
		}
	default:
		return tok, nil
	}
}

func validateIJSON(value any, path string) error {
	switch v := value.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		s := v.String()
		if !strings.ContainsAny(s, ".eE") {
			i, err := strconv.ParseInt(s, 10, 64)
			if err != nil || i > (1<<53)-1 || i < -((1<<53)-1) {
				return fmt.Errorf("%s: integer exceeds interoperable IEEE-754 safe range", path)
			}
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("%s: number is not finite IEEE-754", path)
		}
		return nil
	case []any:
		for i, item := range v {
			if err := validateIJSON(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for key, item := range v {
			if err := validateIJSON(item, path+"."+key); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: unsupported JSON value type", path)
	}
}

func require(condition bool, code, message string, level int) error {
	if !condition {
		return fail(code, message, level)
	}
	return nil
}

func validateDigest(value any, field string) error {
	s, ok := value.(string)
	if !ok || !digestRE.MatchString(s) {
		return fail("ERR_INVALID_FIELD_TYPE", field+" must be an algorithm-tagged lowercase hexadecimal digest", 0)
	}
	parts := strings.SplitN(s, ":", 2)
	if parts[0] == "sha256" && len(parts[1]) != 64 {
		return fail("ERR_INVALID_FIELD_TYPE", field+" sha256 digest must contain 64 hex characters", 0)
	}
	return nil
}

func validateWhat(value any) error {
	if _, ok := value.(string); ok {
		return validateDigest(value, "what")
	}
	obj, ok := value.(map[string]any)
	if !ok || len(obj) == 0 {
		return fail("ERR_INVALID_FIELD_TYPE", "what must be a non-empty object or algorithm-tagged digest", 0)
	}
	if claim, exists := obj["claim"]; exists {
		s, ok := claim.(string)
		if !ok || s == "" {
			return fail("ERR_INVALID_FIELD_TYPE", "what.claim must be a non-empty string", 0)
		}
	}
	return nil
}

func validateRef(value any, allowNull bool) error {
	if value == nil {
		if allowNull {
			return nil
		}
		return fail("ERR_MISSING_REQUIRED_FIELD", "ref must not be null", 0)
	}
	if _, ok := value.(string); ok {
		return validateDigest(value, "ref")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return fail("ERR_INVALID_FIELD_TYPE", "ref must be null, a digest, or a typed reference object", 0)
	}
	kind, hasType := obj["type"].(string)
	_, hasValue := obj["value"]
	if !hasType || kind == "" || !hasValue {
		return fail("ERR_MISSING_REQUIRED_FIELD", "ref object requires non-empty type and value", 0)
	}
	if hash, ok := obj["hash"]; ok {
		if err := validateDigest(hash, "ref.hash"); err != nil {
			return err
		}
	}
	return nil
}

func validateShape(event map[string]any) error {
	for key := range event {
		if !topLevel[key] {
			return fail("ERR_INVALID_FIELD_TYPE", "unknown top-level member: "+key+"; use ext for extensions", 0)
		}
	}
	for _, field := range []string{"jep", "verb", "who", "when", "nonce"} {
		if _, ok := event[field]; !ok {
			return fail("ERR_MISSING_REQUIRED_FIELD", "missing required field: "+field, 0)
		}
	}
	if _, ok := event["sig"]; !ok {
		return fail("ERR_SIGNATURE_MISSING", "missing required field: sig", 1)
	}
	if event["jep"] != "1" {
		return fail("ERR_UNSUPPORTED_JEP_VERSION", "jep must be '1'", 0)
	}
	verb, ok := event["verb"].(string)
	if !ok {
		return fail("ERR_INVALID_FIELD_TYPE", "verb must be a string", 0)
	}
	if verb != "J" && verb != "D" && verb != "T" && verb != "V" {
		return fail("ERR_UNKNOWN_VERB", "verb must be J/D/T/V", 0)
	}
	who, ok := event["who"].(string)
	if !ok || who == "" {
		return fail("ERR_INVALID_FIELD_TYPE", "who must be a non-empty actor identifier string", 0)
	}
	when, ok := event["when"].(json.Number)
	if !ok || strings.ContainsAny(when.String(), ".eE") {
		return fail("ERR_INVALID_TIMESTAMP", "when must be an integer Unix timestamp", 0)
	}
	if _, err := strconv.ParseInt(when.String(), 10, 64); err != nil {
		return fail("ERR_INVALID_TIMESTAMP", "when must be an integer Unix timestamp", 0)
	}
	nonce, ok := event["nonce"].(string)
	if !ok || !uuidV4RE.MatchString(nonce) {
		return fail("ERR_INVALID_FIELD_TYPE", "nonce must be a canonical lowercase UUIDv4 string", 0)
	}
	sig, ok := event["sig"].(string)
	if !ok || sig == "" {
		return fail("ERR_SIGNATURE_CONTAINER_INVALID", "baseline sig must be a non-empty detached compact JWS string", 1)
	}
	parts := strings.Split(sig, ".")
	if len(parts) != 3 || parts[1] != "" || !b64uRE.MatchString(parts[0]) || !b64uRE.MatchString(parts[2]) {
		return fail("ERR_SIGNATURE_CONTAINER_INVALID", "baseline sig must use detached compact JWS shape", 1)
	}
	if aud, exists := event["aud"]; exists {
		s, ok := aud.(string)
		if !ok || s == "" {
			return fail("ERR_INVALID_FIELD_TYPE", "aud must be a non-empty string", 0)
		}
	}
	if ref, exists := event["ref"]; exists {
		if err := validateRef(ref, true); err != nil {
			return err
		}
	}
	if ext, exists := event["ext"]; exists {
		obj, ok := ext.(map[string]any)
		if !ok {
			return fail("ERR_INVALID_FIELD_TYPE", "ext must be an object", 0)
		}
		for id, value := range obj {
			if id == "" {
				return fail("ERR_INVALID_FIELD_TYPE", "extension identifiers must be non-empty strings", 0)
			}
			if _, ok := value.(map[string]any); !ok {
				return fail("ERR_INVALID_FIELD_TYPE", "extension values must be objects", 0)
			}
		}
	}
	if critical, exists := event["ext_crit"]; exists {
		items, ok := critical.([]any)
		if !ok {
			return fail("ERR_INVALID_FIELD_TYPE", "ext_crit must be an array", 0)
		}
		seen := map[string]bool{}
		for _, item := range items {
			s, ok := item.(string)
			if !ok || s == "" || seen[s] {
				return fail("ERR_INVALID_FIELD_TYPE", "ext_crit entries must be unique non-empty strings", 0)
			}
			seen[s] = true
		}
	}

	what, exists := event["what"]
	if !exists || what == nil {
		return fail("ERR_MISSING_REQUIRED_FIELD", verb+" events require a non-null what member", 0)
	}
	if err := validateWhat(what); err != nil {
		return err
	}
	whatObject, objectForm := what.(map[string]any)
	switch verb {
	case "D":
		if _, ok := event["ref"]; !ok {
			return fail("ERR_MISSING_REQUIRED_FIELD", "D events require ref in the v0.6 baseline shape", 0)
		}
		if objectForm {
			for _, field := range []string{"claim", "delegatee", "scope"} {
				if _, ok := whatObject[field]; !ok {
					return fail("ERR_MISSING_REQUIRED_FIELD", "D event requires what."+field, 0)
				}
			}
			delegatee, ok := whatObject["delegatee"].(string)
			if !ok || delegatee == "" || whatObject["scope"] == nil {
				return fail("ERR_INVALID_FIELD_TYPE", "D delegatee must be non-empty and scope must not be null", 0)
			}
		}
	case "T":
		if _, ok := event["ref"]; !ok {
			return fail("ERR_MISSING_REQUIRED_FIELD", "T events require ref in the v0.6 baseline shape", 0)
		}
		if objectForm {
			for _, field := range []string{"claim", "target", "termination_scope"} {
				if _, ok := whatObject[field]; !ok {
					return fail("ERR_MISSING_REQUIRED_FIELD", "T event requires what."+field, 0)
				}
			}
			scope, ok := whatObject["termination_scope"].(string)
			if whatObject["target"] == nil || !ok || scope == "" {
				return fail("ERR_INVALID_FIELD_TYPE", "T target must not be null and termination_scope must be non-empty", 0)
			}
		}
	case "V":
		ref, ok := event["ref"]
		if !ok || ref == nil {
			return fail("ERR_MISSING_REQUIRED_FIELD", "V events require a non-null ref", 0)
		}
		if objectForm {
			scopeValue, ok := whatObject["verification_scope"]
			if !ok {
				return fail("ERR_MISSING_REQUIRED_FIELD", "V event requires what.verification_scope", 0)
			}
			scopes, ok := scopeValue.([]any)
			if !ok || len(scopes) == 0 {
				return fail("ERR_INVALID_FIELD_TYPE", "verification_scope must be a non-empty array", 0)
			}
			seen := map[string]bool{}
			for _, item := range scopes {
				s, ok := item.(string)
				if !ok || s == "" || seen[s] {
					return fail("ERR_INVALID_FIELD_TYPE", "verification scopes must be unique non-empty strings", 0)
				}
				seen[s] = true
			}
		}
	}
	return nil
}

func resultFor(err error) validationResult {
	if err == nil {
		return validationResult{
			Valid: true, Level: 0, Mode: "structural", Profile: coreProfile,
			ConformanceClass: conformanceClass, Scopes: []string{"syntax"},
			EventHash: nil, Warnings: []any{}, Errors: []validationError{},
		}
	}
	var f fault
	if !errors.As(err, &f) {
		f = fault{code: "ERR_INVALID_JSON", message: err.Error(), level: 0}
	}
	return validationResult{
		Valid: false, Level: 0, Mode: "structural", Profile: coreProfile,
		ConformanceClass: conformanceClass, Scopes: []string{}, EventHash: nil,
		Warnings: []any{}, Errors: []validationError{{Code: f.code, Message: f.message, Level: f.level, Recoverable: false}},
	}
}

func validateBytes(raw []byte) validationResult {
	value, err := parseJSONUnique(raw)
	if err != nil {
		return resultFor(err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return resultFor(fail("ERR_INVALID_FIELD_TYPE", "a JEP event must be a JSON object", 0))
	}
	if wrapped, ok := object["event"].(map[string]any); ok {
		object = wrapped
	}
	return resultFor(validateShape(object))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run jep_validate.go <event-or-vector.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	output := validateBytes(raw)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
	if !output.Valid {
		os.Exit(1)
	}
}
