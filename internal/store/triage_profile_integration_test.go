//go:build integration

package store

import (
	"context"
	"encoding/json"
	"testing"
)

func TestTriageProfileCRUD(t *testing.T) {
	ctx := context.Background()
	s := setupTestStore(t)

	weightsJSON := json.RawMessage(`{"cvss":0.25,"epss":0.25,"lev":0.10,"kev":0.10,"patch":0.10,"age":0.05,"exploitdb":0.10,"exploitability":0.05}`)
	thresholdsJSON := json.RawMessage(`{"critical":0.80,"high":0.60,"medium":0.35}`)
	ssvcJSON := json.RawMessage(`{"Act":"Critical","Attend":"High","Track*":"Medium","Track":"Low"}`)

	t.Run("Create", func(t *testing.T) {
		row := &TriageProfileRow{
			Name:        "test-profile",
			Description: "A test profile",
			Base:        "default",
			Weights:     weightsJSON,
			Thresholds:  thresholdsJSON,
			SSVCMapping: &ssvcJSON,
		}

		created, err := s.CreateTriageProfile(ctx, row)
		if err != nil {
			t.Fatalf("CreateTriageProfile failed: %v", err)
		}
		if created.ID == 0 {
			t.Error("expected non-zero ID")
		}
		if created.Name != "test-profile" {
			t.Errorf("expected name 'test-profile', got %q", created.Name)
		}
		if created.Base != "default" {
			t.Errorf("expected base 'default', got %q", created.Base)
		}
	})

	t.Run("Create_DuplicateName", func(t *testing.T) {
		row := &TriageProfileRow{
			Name:       "test-profile",
			Weights:    weightsJSON,
			Thresholds: thresholdsJSON,
		}
		_, err := s.CreateTriageProfile(ctx, row)
		if err == nil {
			t.Fatal("expected error for duplicate name, got nil")
		}
	})

	t.Run("Get", func(t *testing.T) {
		got, err := s.GetTriageProfile(ctx, "test-profile")
		if err != nil {
			t.Fatalf("GetTriageProfile failed: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil profile")
		}
		if got.Description != "A test profile" {
			t.Errorf("expected description 'A test profile', got %q", got.Description)
		}
	})

	t.Run("Get_NotFound", func(t *testing.T) {
		got, err := s.GetTriageProfile(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil for non-existent profile")
		}
	})

	t.Run("List", func(t *testing.T) {
		profiles, err := s.ListTriageProfiles(ctx)
		if err != nil {
			t.Fatalf("ListTriageProfiles failed: %v", err)
		}
		if len(profiles) < 1 {
			t.Error("expected at least 1 profile")
		}
		found := false
		for _, p := range profiles {
			if p.Name == "test-profile" {
				found = true
				break
			}
		}
		if !found {
			t.Error("test-profile not found in list")
		}
	})

	t.Run("Update", func(t *testing.T) {
		row := &TriageProfileRow{
			Description: "Updated description",
			Weights:     weightsJSON,
			Thresholds:  thresholdsJSON,
		}
		updated, err := s.UpdateTriageProfile(ctx, "test-profile", row)
		if err != nil {
			t.Fatalf("UpdateTriageProfile failed: %v", err)
		}
		if updated == nil {
			t.Fatal("expected non-nil result")
		}
		if updated.Description != "Updated description" {
			t.Errorf("expected 'Updated description', got %q", updated.Description)
		}
		if !updated.UpdatedAt.After(updated.CreatedAt) {
			t.Error("expected updated_at > created_at")
		}
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		row := &TriageProfileRow{
			Weights:    weightsJSON,
			Thresholds: thresholdsJSON,
		}
		updated, err := s.UpdateTriageProfile(ctx, "nonexistent", row)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated != nil {
			t.Error("expected nil for non-existent profile update")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := s.DeleteTriageProfile(ctx, "test-profile")
		if err != nil {
			t.Fatalf("DeleteTriageProfile failed: %v", err)
		}

		// Verify it's gone
		got, err := s.GetTriageProfile(ctx, "test-profile")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil after delete")
		}
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		err := s.DeleteTriageProfile(ctx, "nonexistent")
		if err == nil {
			t.Fatal("expected error for deleting non-existent profile")
		}
	})
}
