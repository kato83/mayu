// Package purl provides utilities for converting Package URLs (purls)
// into OSV ecosystem and package name pairs.
//
// The conversion logic mirrors the approach used by OSV.dev:
// https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py
package purl

import (
	"fmt"

	packageurl "github.com/package-url/packageurl-go"
)

// ParsedPURL holds the ecosystem, package name, and version extracted from a purl.
type ParsedPURL struct {
	Ecosystem string
	Package   string
	Version   string
}

// ecosystemPURL maps purl type + namespace to OSV ecosystem name.
type ecosystemPURL struct {
	Type      string
	Namespace string
}

// purlToEcosystem maps (type, namespace) → OSV ecosystem.
// Based on: https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py
var purlToEcosystem = map[ecosystemPURL]string{
	{"rpm", "almalinux"}:                    "AlmaLinux",
	{"rpm", "azure-linux"}:                  "Azure Linux",
	{"apk", "alpaquita"}:                    "Alpaquita",
	{"apk", "alpine"}:                       "Alpine",
	{"apk", "bellsoft-hardened-containers"}: "BellSoft Hardened Containers",
	{"bitnami", ""}:                         "Bitnami",
	{"apk", "chainguard"}:                   "Chainguard",
	{"conan", ""}:                           "ConanCenter",
	{"cran", ""}:                            "CRAN",
	{"cargo", ""}:                           "crates.io",
	{"deb", "echo"}:                         "Echo",
	{"deb", "debian"}:                       "Debian",
	{"dhi", ""}:                             "Docker Hardened Images",
	{"golang", ""}:                          "Go",
	{"hackage", ""}:                         "Hackage",
	{"hex", ""}:                             "Hex",
	{"julia", ""}:                           "Julia",
	{"rpm", "mageia"}:                       "Mageia",
	{"maven", ""}:                           "Maven",
	{"apk", "minimos"}:                      "MinimOS",
	{"npm", ""}:                             "npm",
	{"nuget", ""}:                           "NuGet",
	{"opam", ""}:                            "opam",
	{"rpm", "openeuler"}:                    "openEuler",
	{"rpm", "opensuse"}:                     "openSUSE",
	{"generic", ""}:                         "OSS-Fuzz",
	{"composer", ""}:                        "Packagist",
	{"pub", ""}:                             "Pub",
	{"pypi", ""}:                            "PyPI",
	{"rpm", "redhat"}:                       "Red Hat",
	{"rpm", "rocky-linux"}:                  "Rocky Linux",
	{"gem", ""}:                             "RubyGems",
	{"rpm", "suse"}:                         "SUSE",
	{"swift", ""}:                           "SwiftURL",
	{"deb", "ubuntu"}:                       "Ubuntu",
	{"apk", "wolfi"}:                        "Wolfi",
	// Gradle maps to Maven ecosystem
	{"gradle", ""}: "Maven",
}

// Parse parses a purl string and returns the OSV ecosystem, package name, and version.
// Returns an error if the purl is invalid or the ecosystem is not recognized.
func Parse(purlStr string) (*ParsedPURL, error) {
	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid purl: %w", err)
	}

	pkg := purl.Name
	version := purl.Version

	// Look up ecosystem by (type, namespace)
	ecosystem, ok := purlToEcosystem[ecosystemPURL{purl.Type, purl.Namespace}]
	if ok {
		return &ParsedPURL{
			Ecosystem: ecosystem,
			Package:   pkg,
			Version:   version,
		}, nil
	}

	// Fall back: try with empty namespace (namespace may be part of package name)
	ecosystem, ok = purlToEcosystem[ecosystemPURL{purl.Type, ""}]
	if !ok {
		return nil, fmt.Errorf("unsupported purl type: %s", purl.Type)
	}

	// For ecosystems with optional namespaces, include namespace in package name
	if purl.Namespace != "" {
		switch purl.Type {
		case "golang":
			pkg = purl.Namespace + "/" + purl.Name
			if purl.Subpath != "" {
				pkg = pkg + "/" + purl.Subpath
			}
		case "composer", "hex", "npm", "swift":
			pkg = purl.Namespace + "/" + purl.Name
		case "maven", "gradle":
			pkg = purl.Namespace + ":" + purl.Name
		default:
			return nil, fmt.Errorf("unexpected namespace %q for purl type %s", purl.Namespace, purl.Type)
		}
	}

	return &ParsedPURL{
		Ecosystem: ecosystem,
		Package:   pkg,
		Version:   version,
	}, nil
}
