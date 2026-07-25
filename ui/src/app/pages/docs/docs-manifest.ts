export interface DocEntry {
  slug: string;
  title: string;
  filename: string;
  filenameJa?: string;
}

export const DOCS_MANIFEST: DocEntry[] = [
  { slug: 'readme', title: 'README', filename: 'docs/README.md', filenameJa: 'docs/README_ja.md' },
  { slug: 'webhooks', title: 'Webhooks', filename: 'docs/docs/webhooks.md', filenameJa: 'docs/docs/webhooks.ja.md' },
  { slug: 'nvd-import-comparison', title: 'NVD Import Comparison', filename: 'docs/docs/nvd-import-comparison.md', filenameJa: 'docs/docs/nvd-import-comparison.ja.md' },
  { slug: 'plan', title: 'Plan', filename: 'docs/docs/PLAN.md' },
  { slug: 'plan-webui', title: 'Plan - Web UI', filename: 'docs/docs/PLAN-webui.md' },
  { slug: 'plan-mitre-cve', title: 'Plan - MITRE CVE', filename: 'docs/docs/plan-mitre-cve.md' },
  { slug: 'audit-plan', title: 'Audit Plan', filename: 'docs/docs/audit-plan.md' },
  { slug: 'epss-integration', title: 'EPSS Integration', filename: 'docs/docs/epss-integration.md' },
  { slug: 'kev-integration', title: 'KEV Integration', filename: 'docs/docs/kev-integration.md' },
  { slug: 'nvd-native-plan', title: 'NVD Native Plan', filename: 'docs/docs/nvd-native-plan.md' },
  { slug: 'import-ghsa-json', title: 'Import GHSA JSON', filename: 'docs/docs/import-ghsa-json.md' },
  { slug: 'i18n', title: 'Internationalization', filename: 'docs/docs/i18n.md' },
  { slug: 'todo-multi-osv-tabs', title: 'TODO - Multi OSV Tabs', filename: 'docs/docs/TODO-multi-osv-tabs.md' },
];
