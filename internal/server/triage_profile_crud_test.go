package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kato83/mayu/internal/store"
)

func TestHandleListTriageProfilesAll(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/profiles", nil)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Profiles []struct {
			Name    string `json:"name"`
			Builtin bool   `json:"builtin"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(resp.Profiles) < 4 {
		t.Errorf("expected at least 4 built-in profiles, got %d", len(resp.Profiles))
	}

	// All built-in profiles should have builtin=true
	for _, p := range resp.Profiles {
		if p.Builtin != true {
			t.Errorf("expected builtin=true for %q", p.Name)
		}
	}
}

func TestHandleCreateTriageProfile(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	body := `{"name":"my-custom","description":"test","weights":{"cvss":0.25,"epss":0.25,"lev":0.10,"kev":0.10,"patch":0.10,"age":0.05,"exploitdb":0.10,"exploitability":0.05},"thresholds":{"critical":0.80,"high":0.60,"medium":0.35}}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateTriageProfile_BuiltinNameRejected(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	body := `{"name":"default","description":"test","weights":{"cvss":1.0,"epss":0,"lev":0,"kev":0,"patch":0,"age":0,"exploitdb":0,"exploitability":0},"thresholds":{"critical":0.80,"high":0.60,"medium":0.35}}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for built-in name, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleDeleteTriageProfile_BuiltinRejected(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/triage/profiles/internet-facing", nil)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for built-in delete, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateTriageProfile_BuiltinRejected(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	body := `{"description":"hacked","weights":{"cvss":1.0,"epss":0,"lev":0,"kev":0,"patch":0,"age":0,"exploitdb":0,"exploitability":0},"thresholds":{"critical":0.80,"high":0.60,"medium":0.35}}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/triage/profiles/default", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for built-in update, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleGetTriageProfile_Builtin(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/profiles/default", nil)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Name    string `json:"name"`
		Builtin bool   `json:"builtin"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Name != "default" {
		t.Errorf("expected name 'default', got %q", resp.Name)
	}
	if !resp.Builtin {
		t.Error("expected builtin=true")
	}
}

func TestHandleGetTriageProfile_NotFound(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/profiles/nonexistent", nil)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateTriageProfile_InvalidWeights(t *testing.T) {
	ms := &mockStore{}
	s := newTestServer(ms)

	// weights don't sum to 1.0
	body := `{"name":"bad-profile","description":"test","weights":{"cvss":0.50,"epss":0.50,"lev":0.50,"kev":0,"patch":0,"age":0,"exploitdb":0,"exploitability":0},"thresholds":{"critical":0.80,"high":0.60,"medium":0.35}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for invalid weights, got %d: %s", w.Code, w.Body.String())
	}
}

// mockStore with CreateTriageProfile returning the row with ID populated.
func init() {
	// The default mockStore.CreateTriageProfile already returns the input row.
	// Override it to populate ID for the test.
	_ = store.TriageProfileRow{}
}
