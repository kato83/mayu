/**
 * Search parameters for the vulnerability search API.
 * Mirrors the query parameters of GET /api/v1/vulnerabilities.
 */
export interface SearchParams {
  /** Search by vulnerability ID (e.g., CVE-2024-1234, GO-2024-2687) */
  id?: string;

  /** Search by package name (e.g., golang.org/x/crypto) */
  package?: string;

  /** Filter by ecosystem (e.g., Go, PyPI, npm) */
  ecosystem?: string;

  /** Search by alias (e.g., CVE-2024-24790) */
  alias?: string;

  /** Search by Package URL (e.g., pkg:golang/golang.org/x/crypto) */
  purl?: string;

  /** Filter by CVSS severity level */
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'none';

  /** Filter by modified date (YYYY-MM-DD or RFC3339) */
  since?: string;

  /** Filter by affected version */
  version?: string;

  /** Maximum number of results (1-1000, default: 20) */
  limit?: number;

  /** Offset for pagination (default: 0) */
  offset?: number;

  /** Comma-separated list of fields to return (e.g., "id,summary,modified,severity,ecosystem") */
  fields?: string;
}
