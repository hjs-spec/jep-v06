package main

import (
	"encoding/json"
	"testing"
)

func validEvent() []byte {
	return []byte(`{"jep":"1","verb":"V","who":"did:example:verifier","when":1742345700,"what":{"verification_scope":["syntax"]},"nonce":"4d0e9f80-3333-4abc-9def-123456789abc","ref":"sha256:4444444444444444444444444444444444444444444444444444444444444444","sig":"a..b"}`)
}

func errorCode(result validationResult) string {
	if len(result.Errors) == 0 {
		return ""
	}
	return result.Errors[0].Code
}

func TestValidLevelZeroEvent(t *testing.T) {
	result := validateBytes(validEvent())
	if !result.Valid || result.Level != 0 || result.EventHash != nil {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDuplicateMemberRejected(t *testing.T) {
	raw := []byte(`{"jep":"1","verb":"J","who":"a","who":"b","when":1,"what":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"f47ac10b-58cc-4372-a567-0e02b2c3d479","sig":"a..b"}`)
	result := validateBytes(raw)
	if result.Valid || errorCode(result) != "ERR_DUPLICATE_MEMBER" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestTerminationRequiresTarget(t *testing.T) {
	var event map[string]any
	if err := json.Unmarshal(validEvent(), &event); err != nil {
		t.Fatal(err)
	}
	event["verb"] = "T"
	event["what"] = map[string]any{"claim": "terminate"}
	raw, _ := json.Marshal(event)
	result := validateBytes(raw)
	if result.Valid || errorCode(result) != "ERR_MISSING_REQUIRED_FIELD" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerificationRequiresScope(t *testing.T) {
	var event map[string]any
	if err := json.Unmarshal(validEvent(), &event); err != nil {
		t.Fatal(err)
	}
	event["what"] = map[string]any{"claim": "verified"}
	raw, _ := json.Marshal(event)
	result := validateBytes(raw)
	if result.Valid || errorCode(result) != "ERR_MISSING_REQUIRED_FIELD" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestUnpairedSurrogateRejected(t *testing.T) {
	raw := []byte(`{"jep":"1","verb":"J","who":"\ud800","when":1,"what":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"f47ac10b-58cc-4372-a567-0e02b2c3d479","sig":"a..b"}`)
	result := validateBytes(raw)
	if result.Valid || errorCode(result) != "ERR_INVALID_JSON" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
