package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"filippo.io/edwards25519"
	"fmt"
	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const baselineClass = "JEP-Baseline-Ed25519-JWS-JCS-0.6"
const chainClass = "JEP-Chain-0.6 Verifier"

type options struct {
	Mode, Trust, Audience, Cache string
	Keys                         map[string]map[string]any
	Now, MaxAge, FutureSkew      int64
}

func defaults() options {
	return options{Mode: "archival", Trust: "none", Now: time.Now().Unix(), MaxAge: 300, FutureSkew: 60, Keys: map[string]map[string]any{}}
}
func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if _, err = parseJSONUnique(raw); err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
func hashEvent(event map[string]any) (string, error) {
	raw, err := canonical(event)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }
func unb64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || b64(b) != s {
		return nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "non-canonical base64url", 1)
	}
	return b, nil
}
func str(v any) string { s, _ := v.(string); return s }
func profile(o options) string {
	if o.Trust == "none" {
		return coreProfile
	}
	return coreProfile + "+local-" + o.Trust
}
func keyFile(path string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	if path == "" {
		return out, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := parseJSONUnique(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fail("ERR_INVALID_FIELD_TYPE", "key file must be an object", 0)
	}
	add := func(name string, value any) error {
		k, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		id := str(k["kid"])
		if id == "" {
			id = name
		}
		if id == "" {
			return fail("ERR_KEY_UNRESOLVED", "missing kid", 1)
		}
		if _, exists := out[id]; exists {
			return fail("ERR_INVALID_FIELD_TYPE", "duplicate key identifier", 0)
		}
		out[id] = k
		return nil
	}
	if list, ok := obj["keys"].([]any); ok {
		for _, k := range list {
			if err := add("", k); err != nil {
				return nil, err
			}
		}
	} else {
		for name, k := range obj {
			if err := add(name, k); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
func verifySignature(event map[string]any, o options) (string, map[string]any, error) {
	parts := strings.Split(str(event["sig"]), ".")
	if len(parts) != 3 || parts[1] != "" {
		return "", nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "expected detached JWS", 1)
	}
	raw, err := unb64(parts[0])
	if err != nil {
		return "", nil, err
	}
	v, err := parseJSONUnique(raw)
	h, ok := v.(map[string]any)
	if err != nil || !ok {
		return "", nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "invalid protected header", 1)
	}
	if _, exists := h["crit"]; exists {
		return "", nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "unsupported JOSE critical header", 1)
	}
	if b, exists := h["b64"]; exists && b != true {
		return "", nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "unencoded JWS payload is unsupported", 1)
	}
	alg, ok := h["alg"].(string)
	if !ok {
		return "", nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "missing alg", 1)
	}
	if alg != "Ed25519" {
		return "", nil, fail("ERR_UNSUPPORTED_SIGNATURE_ALG", "baseline requires Ed25519", 1)
	}
	kid := str(h["kid"])
	if kid == "" {
		return "", nil, fail("ERR_SIGNATURE_CONTAINER_INVALID", "missing kid", 1)
	}
	k, ok := o.Keys[kid]
	if !ok {
		return "", nil, fail("ERR_KEY_UNRESOLVED", "key not found: "+kid, 1)
	}
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
		return "", nil, fail("ERR_ALG_KEY_TYPE_MISMATCH", "expected OKP/Ed25519 key", 1)
	}
	if a := k["alg"]; a != nil && a != "Ed25519" {
		return "", nil, fail("ERR_ALG_PROFILE_MISMATCH", "inconsistent JWK alg", 1)
	}
	if u := k["use"]; u != nil && u != "sig" {
		return "", nil, fail("ERR_PROHIBITED_SIGNATURE_ALG", "key is not for signatures", 1)
	}
	if ops := k["key_ops"]; ops != nil {
		items, ok := ops.([]any)
		allowed := false
		for _, v := range items {
			if v == "verify" {
				allowed = true
			}
		}
		if !ok || !allowed {
			return "", nil, fail("ERR_PROHIBITED_SIGNATURE_ALG", "verification not permitted", 1)
		}
	}
	x, ok := k["x"].(string)
	if !ok {
		return "", nil, fail("ERR_ALG_KEY_TYPE_MISMATCH", "missing public key", 1)
	}
	pub, err := unb64(x)
	if err != nil {
		return "", nil, err
	}
	if len(pub) != 32 {
		return "", nil, fail("ERR_ALG_KEY_TYPE_MISMATCH", "key must be 32 bytes", 1)
	}
	sig, err := unb64(parts[2])
	if err != nil {
		return "", nil, err
	}
	if len(sig) != 64 {
		return "", nil, fail("ERR_SIGNATURE_INVALID", "signature must be 64 bytes", 1)
	}
	// Reject non-canonical and small-order public keys even if the underlying verifier accepts them.
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil || !bytes.Equal(p.Bytes(), pub) || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return "", nil, fail("ERR_SIGNATURE_INVALID", "invalid Ed25519 public key", 1)
	}
	unsigned := map[string]any{}
	for key, value := range event {
		if key != "sig" {
			unsigned[key] = value
		}
	}
	payload, err := canonical(unsigned)
	if err != nil {
		return "", nil, fail("ERR_CANONICALIZATION_FAILED", err.Error(), 1)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+b64(payload)), sig) {
		return "", nil, fail("ERR_SIGNATURE_INVALID", "signature verification failed", 1)
	}
	return kid, k, nil
}
func actorBinding(event map[string]any, kid string, k map[string]any, trust string) error {
	if trust == "none" {
		return nil
	}
	if k["revoked"] == true {
		return fail("ERR_KEY_REVOKED", "key revoked", 2)
	}
	actor := str(event["who"])
	switch trust {
	case "kid-prefix":
		if strings.SplitN(kid, "#", 2)[0] == actor {
			return nil
		}
	case "inline":
		if k["actor"] == actor {
			return nil
		}
		if actors, ok := k["actors"].([]any); ok {
			for _, v := range actors {
				if v == actor {
					return nil
				}
			}
		}
	default:
		return fail("ERR_TRUST_PROFILE_UNSUPPORTED", "unknown trust profile", 2)
	}
	return fail("ERR_KEY_NOT_BOUND_TO_ACTOR", "key not bound to actor", 2)
}
func extensions(event map[string]any) error {
	critical, _ := event["ext_crit"].([]any)
	ext, _ := event["ext"].(map[string]any)
	for _, v := range critical {
		id := str(v)
		if _, ok := ext[id]; !ok {
			return fail("ERR_EXTENSION_SCHEMA_INVALID", "critical extension absent: "+id, 3)
		}
		return fail("ERR_UNKNOWN_CRITICAL_EXTENSION", "no handler for critical extension: "+id, 3)
	}
	return nil
}
func nonceContext(event map[string]any, p string) string {
	var key strings.Builder
	key.WriteString("v2:")
	for _, value := range []string{str(event["who"]), str(event["aud"]), p, str(event["nonce"])} {
		fmt.Fprintf(&key, "%d:%s", len(value), value)
	}
	return key.String()
}
func legacyNonceContext(event map[string]any, p string) string {
	return strings.Join([]string{str(event["who"]), str(event["aud"]), p, str(event["nonce"])}, "\x1f")
}
func replayPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve existing aliases, including a symlink at the cache filename.
	if real, err := filepath.EvalSymlinks(absolute); err == nil {
		return real, nil
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(real, filepath.Base(absolute)), nil
}
func consume(path, key string, legacyKeys ...string) error {
	path, err := replayPath(path)
	if err != nil {
		return err
	}
	lock := path + ".consume-lock"
	if err := os.Mkdir(lock, 0700); err != nil {
		return err
	}
	defer os.Remove(lock)
	values := []string{}
	raw, err := os.ReadFile(path)
	if err == nil {
		v, e := parseJSONUnique(raw)
		if e != nil {
			return e
		}
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("cache must be an array")
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("cache entries must be strings")
			}
			if s == key {
				return fail("ERR_NONCE_REPLAY", "nonce already consumed", 3)
			}
			for _, legacy := range legacyKeys {
				if s == legacy {
					return fail("ERR_NONCE_REPLAY", "nonce already consumed in legacy cache", 3)
				}
			}
			values = append(values, s)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	values = append(values, key)
	sort.Strings(values)
	raw, _ = json.Marshal(values)
	f, err := os.CreateTemp(filepath.Dir(path), ".jep-cache-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func eventResult(raw []byte, o options) validationResult {
	r := validationResult{Level: 0, Mode: o.Mode, Profile: profile(o), ConformanceClass: baselineClass, Scopes: []string{}, Warnings: []any{}, Errors: []validationError{}}
	reject := func(err error) validationResult {
		var f fault
		if !errors.As(err, &f) {
			f = fault{"ERR_INVALID_JSON", err.Error(), 0}
		}
		r.Errors = []validationError{{Code: f.code, Message: f.message, Level: f.level}}
		return r
	}
	if o.Mode != "archival" && o.Mode != "acceptance" {
		return reject(fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "unknown mode", 4))
	}
	v, err := parseJSONUnique(raw)
	if err != nil {
		return reject(err)
	}
	event, ok := v.(map[string]any)
	if !ok {
		return reject(fail("ERR_INVALID_FIELD_TYPE", "event must be an object", 0))
	}
	if wrapped, exists := event["event"]; exists {
		event, ok = wrapped.(map[string]any)
		if !ok {
			return reject(fail("ERR_INVALID_FIELD_TYPE", "event wrapper must contain object", 0))
		}
	}
	if err = validateShape(event); err != nil {
		return reject(err)
	}
	r.Scopes = append(r.Scopes, "syntax")
	hash, err := hashEvent(event)
	if err != nil {
		return reject(fail("ERR_CANONICALIZATION_FAILED", err.Error(), 1))
	}
	r.EventHash = &hash
	kid, k, err := verifySignature(event, o)
	if err != nil {
		return reject(err)
	}
	r.Level = 1
	r.Scopes = append(r.Scopes, "cryptographic")
	if err = actorBinding(event, kid, k, o.Trust); err != nil {
		return reject(err)
	}
	if o.Trust != "none" {
		r.Level = 2
		r.Scopes = append(r.Scopes, "actor_binding")
	}
	if o.Mode == "acceptance" {
		if o.MaxAge < 0 || o.FutureSkew < 0 {
			return reject(fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "invalid freshness configuration", 4))
		}
		when, _ := event["when"].(json.Number).Int64()
		if when < o.Now-o.MaxAge {
			return reject(fail("ERR_EVENT_EXPIRED", "event too old", 3))
		}
		if when > o.Now+o.FutureSkew {
			return reject(fail("ERR_TIMESTAMP_OUT_OF_WINDOW", "event in future", 3))
		}
		if o.Cache == "" {
			return reject(fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "acceptance requires persistent replay cache", 3))
		}
	}
	if o.Audience != "" && event["aud"] != o.Audience {
		return reject(fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "audience mismatch", 4))
	}
	if err = extensions(event); err != nil {
		return reject(err)
	}
	if o.Mode == "acceptance" {
		if err = consume(o.Cache, nonceContext(event, r.Profile), legacyNonceContext(event, r.Profile)); err != nil {
			var f fault
			if !errors.As(err, &f) {
				err = fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "replay cache unavailable", 3)
			}
			return reject(err)
		}
	}
	r.Valid = true
	return r
}
func refDigest(v any) string {
	if s, ok := v.(string); ok && digestRE.MatchString(s) {
		return s
	}
	if obj, ok := v.(map[string]any); ok {
		if s := refDigest(obj["hash"]); s != "" {
			return s
		}
		if s, ok := obj["value"].(string); ok {
			return refDigest(s)
		}
	}
	return ""
}

type chainResult struct {
	validationResult
	EventCount    int                `json:"event_count"`
	Results       []validationResult `json:"results"`
	LogAssumption string             `json:"log_assumption"`
	Terminated    []string           `json:"terminated_references,omitempty"`
}

func chainBytes(raw []byte, o options, assumption string) chainResult {
	r := chainResult{validationResult: validationResult{Mode: "chain", Profile: profile(o), ConformanceClass: chainClass, Scopes: []string{}, Warnings: []any{}, Errors: []validationError{}}, Results: []validationResult{}, LogAssumption: assumption}
	reject := func(code, message string, level int) chainResult {
		r.Valid = false
		r.Errors = []validationError{{Code: code, Message: message, Level: level}}
		return r
	}
	if assumption != "partial" && assumption != "complete" {
		return reject("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "unknown log assumption", 4)
	}
	events := []map[string]any{}
	hashes := map[string]bool{}
	o.Mode = "archival"
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		v, err := parseJSONUnique(line)
		if err != nil {
			var f fault
			if errors.As(err, &f) {
				return reject(f.code, f.message, f.level)
			}
			return reject("ERR_INVALID_JSON", err.Error(), 0)
		}
		e, ok := v.(map[string]any)
		if !ok {
			return reject("ERR_INVALID_FIELD_TYPE", "chain member must be object", 0)
		}
		events = append(events, e)
	}
	r.EventCount = len(events)
	if len(events) == 0 {
		return reject("ERR_MISSING_REQUIRED_FIELD", "empty chain", 0)
	}
	r.Level = 4
	for _, e := range events {
		line, _ := json.Marshal(e)
		v := eventResult(line, o)
		r.Results = append(r.Results, v)
		if v.Level < r.Level {
			r.Level = v.Level
		}
		if !v.Valid {
			r.Scopes = v.Scopes
			r.Errors = v.Errors
			return r
		}
		hashes[*v.EventHash] = true
	}
	r.Scopes = []string{"syntax", "cryptographic"}
	if r.Level >= 2 {
		r.Scopes = append(r.Scopes, "actor_binding")
	}
	seen := map[string]bool{}
	terminated := map[string]bool{}
	adj := map[string]string{}
	for i, e := range events {
		h := *r.Results[i].EventHash
		nonce := nonceContext(e, r.Profile)
		if seen[nonce] {
			return reject("ERR_NONCE_REPLAY", "duplicate nonce context", 3)
		}
		seen[nonce] = true
		target := refDigest(e["ref"])
		if target != "" {
			if !hashes[target] {
				return reject("ERR_REF_UNRESOLVED", "reference not found: "+target, 3)
			}
			adj[h] = target
			if (e["verb"] == "J" || e["verb"] == "D") && terminated[target] {
				return reject("ERR_TERMINATED_REFERENCE_REUSED", "terminated reference reused", 3)
			}
		}
		if e["verb"] == "T" {
			what, _ := e["what"].(map[string]any)
			t := refDigest(what["target"])
			if t == "" {
				t = target
			}
			if t == "" {
				return reject("ERR_MISSING_REQUIRED_FIELD", "termination lacks digest target", 3)
			}
			if !hashes[t] {
				return reject("ERR_REF_UNRESOLVED", "termination target not found", 3)
			}
			terminated[t] = true
		}
	}
	for start := range adj {
		path := map[string]bool{}
		for n := start; n != ""; n = adj[n] {
			if path[n] {
				return reject("ERR_CYCLE_DETECTED", "reference cycle", 3)
			}
			path[n] = true
		}
	}
	if r.Level >= 2 {
		r.Level = 3
	}
	r.Scopes = append(r.Scopes, "chain_integrity", "extension_processing")
	for h := range terminated {
		r.Terminated = append(r.Terminated, h)
	}
	sort.Strings(r.Terminated)
	r.Valid = true
	return r
}
