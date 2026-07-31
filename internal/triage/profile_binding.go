package triage

import "time"

// ServerProfileBinding associates a triage profile with a specific server/asset.
type ServerProfileBinding struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	ServerLabel string    `json:"server_label"`
	Environment string    `json:"environment,omitempty"`
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

	// ServerLabel is the server/asset label within the project.
	ServerLabel string
}

// BindingStore defines the persistence interface for profile bindings.
type BindingStore interface {
	CreateBinding(binding *ServerProfileBinding) error
	GetBindingByServer(projectID int64, serverLabel string) (*ServerProfileBinding, error)
	ListBindingsByProject(projectID int64) ([]ServerProfileBinding, error)
	DeleteBinding(projectID int64, serverLabel string) error
}

// ResolveProfile determines which profile to use for a given triage context.
// Priority: ExplicitProfile > ServerBinding > ProjectBinding > Default
func (e *Engine) ResolveProfile(opts *ResolveOpts, bindingStore BindingStore) (*Profile, string) {
	if opts == nil {
		return e.profile, "default"
	}

	// 1. Explicit profile (highest priority)
	if opts.ExplicitProfile != "" {
		p := findProfileByName(opts.ExplicitProfile)
		if p != nil {
			return p, "explicit"
		}
		// If explicit not found, fall through to default
	}

	// 2. Server-level binding
	if bindingStore != nil && opts.ProjectID > 0 && opts.ServerLabel != "" {
		binding, err := bindingStore.GetBindingByServer(opts.ProjectID, opts.ServerLabel)
		if err == nil && binding != nil {
			p := findProfileByName(binding.ProfileName)
			if p != nil {
				return p, "server"
			}
		}
	}

	// 3. Default profile
	return e.profile, "default"
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

// InMemoryBindingStore is a simple in-memory store for profile bindings.
// Used for testing and CLI single-run scenarios.
type InMemoryBindingStore struct {
	bindings []ServerProfileBinding
}

// NewInMemoryBindingStore creates a new in-memory binding store.
func NewInMemoryBindingStore() *InMemoryBindingStore {
	return &InMemoryBindingStore{}
}

func (s *InMemoryBindingStore) CreateBinding(binding *ServerProfileBinding) error {
	// Upsert: remove existing binding for same project+server
	s.DeleteBinding(binding.ProjectID, binding.ServerLabel)
	binding.CreatedAt = time.Now()
	binding.UpdatedAt = time.Now()
	s.bindings = append(s.bindings, *binding)
	return nil
}

func (s *InMemoryBindingStore) GetBindingByServer(projectID int64, serverLabel string) (*ServerProfileBinding, error) {
	for i := range s.bindings {
		if s.bindings[i].ProjectID == projectID && s.bindings[i].ServerLabel == serverLabel {
			return &s.bindings[i], nil
		}
	}
	return nil, nil
}

func (s *InMemoryBindingStore) ListBindingsByProject(projectID int64) ([]ServerProfileBinding, error) {
	var result []ServerProfileBinding
	for _, b := range s.bindings {
		if b.ProjectID == projectID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (s *InMemoryBindingStore) DeleteBinding(projectID int64, serverLabel string) error {
	for i := range s.bindings {
		if s.bindings[i].ProjectID == projectID && s.bindings[i].ServerLabel == serverLabel {
			s.bindings = append(s.bindings[:i], s.bindings[i+1:]...)
			return nil
		}
	}
	return nil
}
