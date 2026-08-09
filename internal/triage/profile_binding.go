package triage

import "time"

// EnvironmentProfileBinding associates a triage profile with a project environment.
type EnvironmentProfileBinding struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	Environment string    `json:"environment"`
	ProfileName string    `json:"profile_name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ResolveOpts specifies the context for profile resolution.
type ResolveOpts struct {
	// ExplicitProfile is a profile name explicitly provided by the user (highest priority).
	ExplicitProfile string

	// ProjectID is the SBOM project ID.
	ProjectID int64

	// Environment is the environment name (e.g., "production", "staging").
	Environment string
}

// EnvironmentBindingStore defines the persistence interface for environment profile bindings.
type EnvironmentBindingStore interface {
	CreateBinding(binding *EnvironmentProfileBinding) error
	GetBindingByEnvironment(projectID int64, environment string) (*EnvironmentProfileBinding, error)
	ListBindingsByProject(projectID int64) ([]EnvironmentProfileBinding, error)
	DeleteBinding(projectID int64, environment string) error
}

// ProjectProfileStore provides project-level default profile lookup.
type ProjectProfileStore interface {
	GetDefaultProfile(projectID int64) (string, error)
}

// ResolveProfile determines which profile to use for a given triage context.
// Priority: ExplicitProfile > EnvironmentBinding > ProjectDefault > EngineDefault
func (e *Engine) ResolveProfile(opts *ResolveOpts, bindingStore EnvironmentBindingStore, projectStore ProjectProfileStore) (*Profile, string) {
	if opts == nil {
		return e.profile, "system_default"
	}

	// 1. Explicit profile (highest priority)
	if opts.ExplicitProfile != "" {
		p := findProfileByName(opts.ExplicitProfile)
		if p != nil {
			return p, "explicit"
		}
	}

	// 2. Environment binding
	if bindingStore != nil && opts.ProjectID > 0 && opts.Environment != "" {
		binding, err := bindingStore.GetBindingByEnvironment(opts.ProjectID, opts.Environment)
		if err == nil && binding != nil {
			p := findProfileByName(binding.ProfileName)
			if p != nil {
				return p, "environment"
			}
		}
	}

	// 3. Project default
	if projectStore != nil && opts.ProjectID > 0 {
		profileName, err := projectStore.GetDefaultProfile(opts.ProjectID)
		if err == nil && profileName != "" {
			p := findProfileByName(profileName)
			if p != nil {
				return p, "project_default"
			}
		}
	}

	// 4. System default
	return e.profile, "system_default"
}

// findProfileByName looks up a profile by name from built-in templates.
func findProfileByName(name string) *Profile {
	for _, t := range BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// InMemoryBindingStore is a simple in-memory store for environment profile bindings.
// Used for testing and CLI single-run scenarios.
type InMemoryBindingStore struct {
	bindings []EnvironmentProfileBinding
}

// NewInMemoryBindingStore creates a new in-memory binding store.
func NewInMemoryBindingStore() *InMemoryBindingStore {
	return &InMemoryBindingStore{}
}

func (s *InMemoryBindingStore) CreateBinding(binding *EnvironmentProfileBinding) error {
	// Upsert: remove existing binding for same project+environment
	_ = s.DeleteBinding(binding.ProjectID, binding.Environment)
	binding.CreatedAt = time.Now()
	binding.UpdatedAt = time.Now()
	s.bindings = append(s.bindings, *binding)
	return nil
}

func (s *InMemoryBindingStore) GetBindingByEnvironment(projectID int64, environment string) (*EnvironmentProfileBinding, error) {
	for i := range s.bindings {
		if s.bindings[i].ProjectID == projectID && s.bindings[i].Environment == environment {
			return &s.bindings[i], nil
		}
	}
	return nil, nil
}

func (s *InMemoryBindingStore) ListBindingsByProject(projectID int64) ([]EnvironmentProfileBinding, error) {
	var result []EnvironmentProfileBinding
	for _, b := range s.bindings {
		if b.ProjectID == projectID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (s *InMemoryBindingStore) DeleteBinding(projectID int64, environment string) error {
	for i := range s.bindings {
		if s.bindings[i].ProjectID == projectID && s.bindings[i].Environment == environment {
			s.bindings = append(s.bindings[:i], s.bindings[i+1:]...)
			return nil
		}
	}
	return nil
}
