// Package i18n provides internationalization utilities for the Mayu API,
// including Accept-Language header parsing and locale negotiation.
package i18n

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// ctxKey is the context key type for storing locale information.
type ctxKey struct{}

// Locale represents a parsed locale preference from Accept-Language.
type Locale struct {
	// Tag is the BCP 47 language tag (e.g., "ja", "ko", "zh-Hans").
	Tag string

	// Quality is the preference weight (0.0 - 1.0). Default is 1.0.
	Quality float64
}

// PreferredLocales returns the negotiated locale list from the request context.
// Returns nil if no non-English locale was requested.
func PreferredLocales(ctx context.Context) []string {
	if v, ok := ctx.Value(ctxKey{}).([]string); ok {
		return v
	}
	return nil
}

// WithLocales attaches locale preferences to a context.
func WithLocales(ctx context.Context, locales []string) context.Context {
	return context.WithValue(ctx, ctxKey{}, locales)
}

// ParseAcceptLanguage parses the Accept-Language header value into a sorted
// list of non-English locale tags (highest quality first).
//
// Examples:
//
//	"ja,en;q=0.9"          → ["ja"]
//	"zh-Hans,ja;q=0.8,en;q=0.5" → ["zh-Hans", "ja"]
//	"en"                   → [] (empty, no translation needed)
//	"*"                    → [] (wildcard, no specific preference)
func ParseAcceptLanguage(header string) []string {
	if header == "" {
		return nil
	}

	var locales []Locale

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		tag := part
		quality := 1.0

		if idx := strings.Index(part, ";"); idx >= 0 {
			tag = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if q, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					quality = q
				}
			}
		}

		// Skip wildcard and zero-quality entries
		if tag == "*" || quality <= 0 {
			continue
		}

		// Normalize: lowercase the primary subtag
		tag = normalizeLocaleTag(tag)

		// Skip English variants (no translation needed)
		if isEnglish(tag) {
			continue
		}

		locales = append(locales, Locale{Tag: tag, Quality: quality})
	}

	// Sort by quality descending (stable for equal qualities preserves header order)
	sort.SliceStable(locales, func(i, j int) bool {
		return locales[i].Quality > locales[j].Quality
	})

	// Deduplicate and extract tags
	seen := make(map[string]bool)
	var result []string
	for _, loc := range locales {
		if !seen[loc.Tag] {
			seen[loc.Tag] = true
			result = append(result, loc.Tag)
		}
	}

	return result
}

// normalizeLocaleTag normalizes a BCP 47 tag for consistent storage lookup.
// Primary subtag is lowercased, script subtag is title-cased.
// e.g., "ZH-hans" → "zh-Hans", "JA" → "ja", "zh-TW" → "zh-TW"
func normalizeLocaleTag(tag string) string {
	parts := strings.Split(tag, "-")
	if len(parts) == 0 {
		return tag
	}

	// Primary language subtag: always lowercase
	parts[0] = strings.ToLower(parts[0])

	if len(parts) >= 2 {
		// If second part is 4 chars, it's a script subtag (title case)
		if len(parts[1]) == 4 {
			parts[1] = strings.ToUpper(parts[1][:1]) + strings.ToLower(parts[1][1:])
		} else {
			// Region subtag: uppercase
			parts[1] = strings.ToUpper(parts[1])
		}
	}

	return strings.Join(parts, "-")
}

// isEnglish returns true if the tag represents an English locale.
func isEnglish(tag string) bool {
	lower := strings.ToLower(tag)
	return lower == "en" || strings.HasPrefix(lower, "en-")
}

// LocaleMiddleware extracts the Accept-Language header and attaches
// the preferred non-English locales to the request context.
// Downstream handlers can retrieve them via PreferredLocales(ctx).
func LocaleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		locales := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
		if len(locales) > 0 {
			r = r.WithContext(WithLocales(r.Context(), locales))
		}
		next.ServeHTTP(w, r)
	})
}
