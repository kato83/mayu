package notification

import (
	"strings"
	"testing"
)

func TestGetSlackTemplate(t *testing.T) {
	tmpl := GetSlackTemplate()
	if tmpl == "" {
		t.Fatal("Slack template is empty")
	}
	if !strings.Contains(tmpl, "blocks") {
		t.Error("Slack template missing 'blocks' key")
	}
	if !strings.Contains(tmpl, "{{Severity}}") {
		t.Error("Slack template missing {{Severity}} placeholder")
	}
	if !strings.Contains(tmpl, "{{ID}}") {
		t.Error("Slack template missing {{ID}} placeholder")
	}
}

func TestGetTeamsTemplate(t *testing.T) {
	tmpl := GetTeamsTemplate()
	if tmpl == "" {
		t.Fatal("Teams template is empty")
	}
	if !strings.Contains(tmpl, "AdaptiveCard") {
		t.Error("Teams template missing 'AdaptiveCard' type")
	}
	if !strings.Contains(tmpl, "{{Severity}}") {
		t.Error("Teams template missing {{Severity}} placeholder")
	}
	if !strings.Contains(tmpl, "{{ID}}") {
		t.Error("Teams template missing {{ID}} placeholder")
	}
}

func TestGetEmailHTMLTemplate(t *testing.T) {
	tmpl := GetEmailHTMLTemplate()
	if tmpl == "" {
		t.Fatal("Email HTML template is empty")
	}
	if !strings.Contains(tmpl, "<!DOCTYPE html>") {
		t.Error("Email template missing DOCTYPE")
	}
	if !strings.Contains(tmpl, "{{Severity}}") {
		t.Error("Email template missing {{Severity}} placeholder")
	}
	if !strings.Contains(tmpl, "{{Summary}}") {
		t.Error("Email template missing {{Summary}} placeholder")
	}
}

func TestPresetTemplates(t *testing.T) {
	templates := PresetTemplates()
	if len(templates) != 3 {
		t.Fatalf("expected 3 templates, got %d", len(templates))
	}

	names := map[TemplateName]bool{}
	for _, tmpl := range templates {
		names[tmpl.Name] = true
		if tmpl.Template == "" {
			t.Errorf("template %q has empty content", tmpl.Name)
		}
		if tmpl.Description == "" {
			t.Errorf("template %q has empty description", tmpl.Name)
		}
		if tmpl.ContentType == "" {
			t.Errorf("template %q has empty content type", tmpl.Name)
		}
	}

	for _, expected := range []TemplateName{TemplateSlack, TemplateTeams, TemplateEmail} {
		if !names[expected] {
			t.Errorf("missing preset template: %q", expected)
		}
	}
}

func TestTemplateFS(t *testing.T) {
	entries, err := TemplateFS.ReadDir("templates")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 template files, got %d", len(entries))
	}

	expectedFiles := map[string]bool{
		"slack.json.tmpl": false,
		"teams.json.tmpl": false,
		"email.html.tmpl": false,
	}
	for _, e := range entries {
		if _, ok := expectedFiles[e.Name()]; ok {
			expectedFiles[e.Name()] = true
		}
	}
	for name, found := range expectedFiles {
		if !found {
			t.Errorf("missing template file: %s", name)
		}
	}
}
