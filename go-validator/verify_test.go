package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSharedManifest(t *testing.T) {
	raw, err := os.ReadFile("../test-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			Name, Kind, Path, Keys string
			Trust                  string `json:"trust_profile"`
			Valid                  bool   `json:"expected_valid"`
			Level                  int    `json:"expected_level"`
			Error                  string `json:"expected_error"`
			Hash                   string `json:"expected_event_hash"`
		}
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			o := defaults()
			o.Keys, err = keyFile(filepath.Join("..", c.Keys))
			if err != nil {
				t.Fatal(err)
			}
			if c.Trust != "" {
				o.Trust = c.Trust
			}
			raw, err := os.ReadFile(filepath.Join("..", c.Path))
			if err != nil {
				t.Fatal(err)
			}
			var result validationResult
			if c.Kind == "chain" {
				result = chainBytes(raw, o, "partial").validationResult
			} else {
				result = eventResult(raw, o)
			}
			if result.Valid != c.Valid || result.Level != c.Level || errorCode(result) != c.Error {
				t.Fatalf("unexpected result %+v", result)
			}
			if c.Hash != "" && (result.EventHash == nil || *result.EventHash != c.Hash) {
				t.Fatal("hash differs")
			}
		})
	}
}
func TestAtomicReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if consume(path, "same-nonce") == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d", accepted.Load())
	}
	if err := consume(path, "same-nonce"); err == nil {
		t.Fatal("replay accepted")
	}
}
func TestAcceptanceChecksBeforeConsume(t *testing.T) {
	raw, _ := os.ReadFile("../test-vectors/interop/control-J.json")
	o := defaults()
	o.Keys, _ = keyFile("../test-vectors/interop/public-keys.json")
	v, _ := parseJSONUnique(raw)
	e := v.(map[string]any)
	if w, ok := e["event"].(map[string]any); ok {
		e = w
	}
	o.Now, _ = e["when"].(json.Number).Int64()
	o.Mode = "acceptance"
	o.Cache = filepath.Join(t.TempDir(), "cache.json")
	o.Audience = "wrong"
	if eventResult(raw, o).Valid {
		t.Fatal("audience accepted")
	}
	o.Audience = ""
	if !eventResult(raw, o).Valid {
		t.Fatal("failed validation consumed nonce")
	}
	if errorCode(eventResult(raw, o)) != "ERR_NONCE_REPLAY" {
		t.Fatal("replay accepted")
	}
}
