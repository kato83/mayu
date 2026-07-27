package model

import "time"

// TranslatedText holds original text alongside its translation for a specific locale.
type TranslatedText struct {
	// Original is the source language text (typically English).
	Original string `json:"original"`

	// Translated is the translated text in the requested locale.
	// Empty string if no translation is available.
	Translated string `json:"translated,omitempty"`

	// Locale is the BCP 47 language tag of the translation (e.g., "ja", "ko").
	Locale string `json:"locale,omitempty"`

	// TranslatedAt is when the translation was generated.
	TranslatedAt *time.Time `json:"translated_at,omitempty"`
}

// VulnerabilityTranslation contains translations for vulnerability text fields.
type VulnerabilityTranslation struct {
	// Locale is the BCP 47 language tag.
	Locale string `json:"locale"`

	// Summary is the translated summary (nil if not translated).
	Summary *string `json:"summary,omitempty"`

	// Details is the translated details (nil if not translated).
	Details *string `json:"details,omitempty"`

	// TranslatedAt is when this translation was generated.
	TranslatedAt time.Time `json:"translated_at"`
}

// KEVTranslation contains translations for KEV entry text fields.
type KEVTranslation struct {
	// Locale is the BCP 47 language tag.
	Locale string `json:"locale"`

	// VulnerabilityName is the translated vulnerability name.
	VulnerabilityName *string `json:"vulnerability_name,omitempty"`

	// ShortDescription is the translated short description.
	ShortDescription *string `json:"short_description,omitempty"`

	// RequiredAction is the translated required action.
	RequiredAction *string `json:"required_action,omitempty"`

	// Notes is the translated notes.
	Notes *string `json:"notes,omitempty"`

	// TranslatedAt is when this translation was generated.
	TranslatedAt time.Time `json:"translated_at"`
}

// NVDDescriptionTranslation contains a translation for an NVD description.
type NVDDescriptionTranslation struct {
	// Locale is the BCP 47 language tag.
	Locale string `json:"locale"`

	// Value is the translated description text.
	Value string `json:"value"`

	// TranslatedAt is when this translation was generated.
	TranslatedAt time.Time `json:"translated_at"`
}

// MITREProblemTypeTranslation contains a translation for a MITRE problem type description.
type MITREProblemTypeTranslation struct {
	// Locale is the BCP 47 language tag.
	Locale string `json:"locale"`

	// Description is the translated description.
	Description string `json:"description"`

	// TranslatedAt is when this translation was generated.
	TranslatedAt time.Time `json:"translated_at"`
}

// MITRECreditTranslation contains a translation for a MITRE credit value.
type MITRECreditTranslation struct {
	// Locale is the BCP 47 language tag.
	Locale string `json:"locale"`

	// Value is the translated credit value.
	Value string `json:"value"`

	// TranslatedAt is when this translation was generated.
	TranslatedAt time.Time `json:"translated_at"`
}
