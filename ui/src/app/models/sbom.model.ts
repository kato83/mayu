export interface SBOMProject {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface SBOMVersion {
  id: number;
  project_id: number;
  version: string;
  environment?: string;
  sbom_format: string;
  component_count: number;
  created_at: string;
}

export interface ScanFinding {
  purl: string;
  name: string;
  version: string;
  ecosystem: string;
  vuln_id: string;
  aliases?: string[];
  severity: string;
  severity_level: number;
  summary: string;
}

export interface SBOMScanResult {
  id: number;
  version_id: number;
  scanned_at: string;
  total_packages: number;
  vulnerable_packages: number;
  total_findings: number;
  new_findings: number;
  resolved_findings: number;
  findings: ScanFinding[];
  status: string;
  trigger: string;
}

export interface ScanDiff {
  new_findings: ScanFinding[];
  resolved_findings: ScanFinding[];
}

export interface CreateProjectRequest {
  name: string;
}

export interface UploadSBOMRequest {
  version: string;
  environment?: string;
  sbom: object;
}

export interface UploadSBOMResponse {
  version: SBOMVersion;
  scan_result: SBOMScanResult;
}
