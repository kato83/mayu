export interface DocEntry {
  slug: string;
  title: string;
  filename: string;
  filenameJa?: string;
}

export const DOCS_MANIFEST: DocEntry[] = [
  { slug: 'readme', title: 'README', filename: 'docs/README.md', filenameJa: 'docs/README_ja.md' },
  { slug: 'webhooks', title: 'Webhooks', filename: 'docs/docs/webhooks.md', filenameJa: 'docs/docs/webhooks.ja.md' },
  {
    slug: 'nvd-import-comparison',
    title: 'NVD Import Comparison',
    filename: 'docs/docs/nvd-import-comparison.md',
    filenameJa: 'docs/docs/nvd-import-comparison.ja.md',
  },
  {
    slug: 'license-policy-example',
    title: 'License Policy Example',
    filename: 'docs/docs/license-policy-example.md',
    filenameJa: 'docs/docs/license-policy-example.ja.md',
  },
  {
    slug: 'translation',
    title: 'Translation (LLM)',
    filename: 'docs/docs/translation.md',
    filenameJa: 'docs/docs/translation.ja.md',
  },
];
