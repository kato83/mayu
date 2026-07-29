package license

// spdxLicenses maps SPDX license identifiers to their Info.
// This covers the most commonly encountered licenses in open-source software.
var spdxLicenses = map[string]Info{
	// Permissive licenses
	"MIT":           {SPDXID: "MIT", Name: "MIT License", Category: Permissive},
	"Apache-2.0":    {SPDXID: "Apache-2.0", Name: "Apache License 2.0", Category: Permissive},
	"BSD-2-Clause":  {SPDXID: "BSD-2-Clause", Name: "BSD 2-Clause \"Simplified\" License", Category: Permissive},
	"BSD-3-Clause":  {SPDXID: "BSD-3-Clause", Name: "BSD 3-Clause \"New\" or \"Revised\" License", Category: Permissive},
	"ISC":           {SPDXID: "ISC", Name: "ISC License", Category: Permissive},
	"Unlicense":     {SPDXID: "Unlicense", Name: "The Unlicense", Category: Permissive},
	"CC0-1.0":       {SPDXID: "CC0-1.0", Name: "Creative Commons Zero v1.0 Universal", Category: Permissive},
	"0BSD":          {SPDXID: "0BSD", Name: "BSD Zero Clause License", Category: Permissive},
	"Zlib":          {SPDXID: "Zlib", Name: "zlib License", Category: Permissive},
	"BSL-1.0":       {SPDXID: "BSL-1.0", Name: "Boost Software License 1.0", Category: Permissive},
	"MIT-0":         {SPDXID: "MIT-0", Name: "MIT No Attribution", Category: Permissive},
	"AFL-3.0":       {SPDXID: "AFL-3.0", Name: "Academic Free License v3.0", Category: Permissive},
	"X11":           {SPDXID: "X11", Name: "X11 License", Category: Permissive},
	"PSF-2.0":       {SPDXID: "PSF-2.0", Name: "Python Software Foundation License 2.0", Category: Permissive},
	"Unicode-3.0":   {SPDXID: "Unicode-3.0", Name: "Unicode License v3", Category: Permissive},
	"BlueOak-1.0.0": {SPDXID: "BlueOak-1.0.0", Name: "Blue Oak Model License 1.0.0", Category: Permissive},
	"CC-BY-4.0":     {SPDXID: "CC-BY-4.0", Name: "Creative Commons Attribution 4.0 International", Category: Permissive},
	"CC-BY-3.0":     {SPDXID: "CC-BY-3.0", Name: "Creative Commons Attribution 3.0 Unported", Category: Permissive},
	"WTFPL":         {SPDXID: "WTFPL", Name: "Do What The F*ck You Want To Public License", Category: Permissive},

	// Weak copyleft licenses
	"MPL-2.0":           {SPDXID: "MPL-2.0", Name: "Mozilla Public License 2.0", Category: WeakCopyleft},
	"LGPL-2.1-only":     {SPDXID: "LGPL-2.1-only", Name: "GNU Lesser General Public License v2.1 only", Category: WeakCopyleft},
	"LGPL-2.1-or-later": {SPDXID: "LGPL-2.1-or-later", Name: "GNU Lesser General Public License v2.1 or later", Category: WeakCopyleft},
	"LGPL-3.0-only":     {SPDXID: "LGPL-3.0-only", Name: "GNU Lesser General Public License v3.0 only", Category: WeakCopyleft},
	"LGPL-3.0-or-later": {SPDXID: "LGPL-3.0-or-later", Name: "GNU Lesser General Public License v3.0 or later", Category: WeakCopyleft},
	"EPL-1.0":           {SPDXID: "EPL-1.0", Name: "Eclipse Public License 1.0", Category: WeakCopyleft},
	"EPL-2.0":           {SPDXID: "EPL-2.0", Name: "Eclipse Public License 2.0", Category: WeakCopyleft},
	"CDDL-1.0":          {SPDXID: "CDDL-1.0", Name: "Common Development and Distribution License 1.0", Category: WeakCopyleft},
	"CDDL-1.1":          {SPDXID: "CDDL-1.1", Name: "Common Development and Distribution License 1.1", Category: WeakCopyleft},
	"CPL-1.0":           {SPDXID: "CPL-1.0", Name: "Common Public License 1.0", Category: WeakCopyleft},

	// Strong copyleft licenses
	"GPL-2.0-only":      {SPDXID: "GPL-2.0-only", Name: "GNU General Public License v2.0 only", Category: StrongCopyleft},
	"GPL-2.0-or-later":  {SPDXID: "GPL-2.0-or-later", Name: "GNU General Public License v2.0 or later", Category: StrongCopyleft},
	"GPL-3.0-only":      {SPDXID: "GPL-3.0-only", Name: "GNU General Public License v3.0 only", Category: StrongCopyleft},
	"GPL-3.0-or-later":  {SPDXID: "GPL-3.0-or-later", Name: "GNU General Public License v3.0 or later", Category: StrongCopyleft},
	"AGPL-3.0-only":     {SPDXID: "AGPL-3.0-only", Name: "GNU Affero General Public License v3.0", Category: StrongCopyleft},
	"AGPL-3.0-or-later": {SPDXID: "AGPL-3.0-or-later", Name: "GNU Affero General Public License v3.0 or later", Category: StrongCopyleft},
	"SSPL-1.0":          {SPDXID: "SSPL-1.0", Name: "Server Side Public License v1", Category: StrongCopyleft},
	"OSL-3.0":           {SPDXID: "OSL-3.0", Name: "Open Software License 3.0", Category: StrongCopyleft},
	"EUPL-1.2":          {SPDXID: "EUPL-1.2", Name: "European Union Public License 1.2", Category: StrongCopyleft},
	"CC-BY-SA-4.0":      {SPDXID: "CC-BY-SA-4.0", Name: "Creative Commons Attribution Share Alike 4.0 International", Category: StrongCopyleft},

	// Deprecated SPDX IDs (still in common use)
	"GPL-2.0":  {SPDXID: "GPL-2.0", Name: "GNU General Public License v2.0 only", Category: StrongCopyleft},
	"GPL-3.0":  {SPDXID: "GPL-3.0", Name: "GNU General Public License v3.0 only", Category: StrongCopyleft},
	"LGPL-2.1": {SPDXID: "LGPL-2.1", Name: "GNU Lesser General Public License v2.1", Category: WeakCopyleft},
	"LGPL-3.0": {SPDXID: "LGPL-3.0", Name: "GNU Lesser General Public License v3.0", Category: WeakCopyleft},
	"AGPL-3.0": {SPDXID: "AGPL-3.0", Name: "GNU Affero General Public License v3.0", Category: StrongCopyleft},
}
