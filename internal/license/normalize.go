package license

import "strings"

// commonAliases maps commonly used (but non-standard) license strings to SPDX IDs.
var commonAliases = map[string]string{
	// MIT variations
	"mit license":     "MIT",
	"the mit license": "MIT",
	"mit":             "MIT",
	"expat":           "MIT",

	// Apache variations
	"apache license 2.0":          "Apache-2.0",
	"apache-2.0":                  "Apache-2.0",
	"apache 2.0":                  "Apache-2.0",
	"apache license, version 2.0": "Apache-2.0",
	"apache software license 2.0": "Apache-2.0",
	"apache 2":                    "Apache-2.0",
	"asl 2.0":                     "Apache-2.0",

	// BSD variations
	"bsd-2-clause":             "BSD-2-Clause",
	"bsd 2-clause":             "BSD-2-Clause",
	"bsd 2-clause license":     "BSD-2-Clause",
	"simplified bsd license":   "BSD-2-Clause",
	"the 2-clause bsd license": "BSD-2-Clause",
	"freebsd license":          "BSD-2-Clause",
	"bsd-3-clause":             "BSD-3-Clause",
	"bsd 3-clause":             "BSD-3-Clause",
	"bsd 3-clause license":     "BSD-3-Clause",
	"new bsd license":          "BSD-3-Clause",
	"modified bsd license":     "BSD-3-Clause",
	"the 3-clause bsd license": "BSD-3-Clause",
	"bsd license":              "BSD-3-Clause",
	"bsd":                      "BSD-3-Clause",

	// ISC
	"isc license": "ISC",
	"isc":         "ISC",

	// CC0
	"cc0-1.0":                              "CC0-1.0",
	"cc0 1.0":                              "CC0-1.0",
	"cc0 1.0 universal":                    "CC0-1.0",
	"creative commons zero v1.0 universal": "CC0-1.0",
	"public domain":                        "CC0-1.0",

	// Unlicense
	"unlicense":     "Unlicense",
	"the unlicense": "Unlicense",

	// MPL
	"mpl-2.0":                    "MPL-2.0",
	"mpl 2.0":                    "MPL-2.0",
	"mozilla public license 2.0": "MPL-2.0",

	// GPL variations
	"gpl-2.0":                         "GPL-2.0-only",
	"gpl-2.0-only":                    "GPL-2.0-only",
	"gpl 2.0":                         "GPL-2.0-only",
	"gnu general public license v2.0": "GPL-2.0-only",
	"gnu gpl v2":                      "GPL-2.0-only",
	"gplv2":                           "GPL-2.0-only",
	"gpl-2.0-or-later":                "GPL-2.0-or-later",
	"gpl v2+":                         "GPL-2.0-or-later",
	"gpl-3.0":                         "GPL-3.0-only",
	"gpl-3.0-only":                    "GPL-3.0-only",
	"gpl 3.0":                         "GPL-3.0-only",
	"gnu general public license v3.0": "GPL-3.0-only",
	"gnu gpl v3":                      "GPL-3.0-only",
	"gplv3":                           "GPL-3.0-only",
	"gpl-3.0-or-later":                "GPL-3.0-or-later",
	"gpl v3+":                         "GPL-3.0-or-later",

	// LGPL variations
	"lgpl-2.1":                               "LGPL-2.1-only",
	"lgpl-2.1-only":                          "LGPL-2.1-only",
	"lgpl 2.1":                               "LGPL-2.1-only",
	"gnu lesser general public license v2.1": "LGPL-2.1-only",
	"lgpl-2.1-or-later":                      "LGPL-2.1-or-later",
	"lgpl-3.0":                               "LGPL-3.0-only",
	"lgpl-3.0-only":                          "LGPL-3.0-only",
	"lgpl 3.0":                               "LGPL-3.0-only",
	"gnu lesser general public license v3.0": "LGPL-3.0-only",
	"lgpl-3.0-or-later":                      "LGPL-3.0-or-later",

	// AGPL variations
	"agpl-3.0":                             "AGPL-3.0-only",
	"agpl-3.0-only":                        "AGPL-3.0-only",
	"agpl 3.0":                             "AGPL-3.0-only",
	"gnu affero general public license v3": "AGPL-3.0-only",
	"agpl-3.0-or-later":                    "AGPL-3.0-or-later",

	// EPL
	"epl-1.0":                    "EPL-1.0",
	"eclipse public license 1.0": "EPL-1.0",
	"epl-2.0":                    "EPL-2.0",
	"eclipse public license 2.0": "EPL-2.0",

	// Zlib
	"zlib":         "Zlib",
	"zlib license": "Zlib",

	// Boost
	"bsl-1.0":                    "BSL-1.0",
	"boost software license 1.0": "BSL-1.0",

	// WTFPL
	"wtfpl": "WTFPL",
	"do what the f*ck you want to public license": "WTFPL",

	// CC-BY
	"cc-by-4.0":                        "CC-BY-4.0",
	"cc by 4.0":                        "CC-BY-4.0",
	"creative commons attribution 4.0": "CC-BY-4.0",
}

// Normalize converts various license string representations to a standard SPDX ID.
// It handles case-insensitive matching, common aliases, and extraneous whitespace.
// Returns the input as-is if no normalization can be applied.
func Normalize(raw string) string {
	if raw == "" {
		return ""
	}

	// Trim whitespace
	trimmed := strings.TrimSpace(raw)

	// Check if it's already a valid SPDX ID (case-sensitive exact match)
	if _, ok := spdxLicenses[trimmed]; ok {
		return trimmed
	}

	// Normalize to lowercase for alias lookup
	lower := strings.ToLower(trimmed)

	// Look up in common aliases
	if spdxID, ok := commonAliases[lower]; ok {
		return spdxID
	}

	// Try case-insensitive match against known SPDX IDs
	for id := range spdxLicenses {
		if strings.EqualFold(trimmed, id) {
			return id
		}
	}

	// Return the trimmed original if no match found
	return trimmed
}
