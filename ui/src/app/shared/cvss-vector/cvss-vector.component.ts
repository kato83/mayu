import { Component, computed, input, signal } from '@angular/core';

import { CVSS_DEFINITIONS, type CvssMetricDefinition, type CvssVersion } from './cvss-vector-definitions';

export interface ParsedMetric {
  key: string;
  value: string;
  definition?: CvssMetricDefinition;
  valueLabel?: string;
  valueDescription?: string;
}

@Component({
  selector: 'app-cvss-vector',
  standalone: true,
  template: `
    <div class="inline">
      <code class="text-xs text-slate-500 dark:text-slate-400 break-all">{{ vector() }}</code>
      @if (parsedMetrics().length > 0) {
        <button
          type="button"
          class="ml-1 text-xs text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
          (click)="toggleExpanded()"
          [attr.aria-expanded]="expanded()"
          [attr.aria-label]="expandLabel"
        >
          @if (expanded()) {
            ▲
          } @else {
            ▼
          }
        </button>
      }
    </div>
    @if (expanded() && parsedMetrics().length > 0) {
      <div class="mt-1">
        <table class="text-xs border-collapse w-full max-w-lg">
          <thead>
            <tr class="text-left text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
              <th class="py-1 whitespace-nowrap pr-3 font-medium" i18n="@@cvssVector.table.metric">Metric</th>
              <th class="py-1 whitespace-nowrap pr-3 font-medium" i18n="@@cvssVector.table.name">Name</th>
              <th class="py-1 whitespace-nowrap font-medium" i18n="@@cvssVector.table.value">Value</th>
            </tr>
          </thead>
          <tbody>
            @for (metric of parsedMetrics(); track metric.key) {
              <tr class="border-b border-slate-100 dark:border-slate-800">
                <td class="py-1 pr-3 font-mono text-slate-600 dark:text-slate-300">{{ metric.key }}</td>
                <td class="py-1 pr-3 text-slate-600 dark:text-slate-300">{{ metric.definition?.name ?? metric.key }}</td>
                <td class="py-1 text-slate-600 dark:text-slate-300">
                  <span class="font-mono">{{ metric.value }}</span>
                  @if (metric.valueLabel) {
                    <span> - {{ metric.valueLabel }}</span>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    }
  `,
})
export class CvssVectorComponent {
  vector = input.required<string>();

  expanded = signal(false);
  expandLabel = $localize`:@@cvssVector.toggleDetails:Toggle vector details`;

  detectedVersion = computed<CvssVersion | null>(() => {
    const v = this.vector();
    if (v.startsWith('CVSS:4.0/')) return '4.0';
    if (v.startsWith('CVSS:3.1/')) return '3.1';
    if (v.startsWith('CVSS:3.0/')) return '3.0';
    // CVSS v2 has no prefix
    if (/^(?:AV|AC|Au|C|I|A):/.test(v)) return '2.0';
    return null;
  });

  parsedMetrics = computed<ParsedMetric[]>(() => {
    const v = this.vector();
    const version = this.detectedVersion();
    if (!version) return [];

    const definitions = CVSS_DEFINITIONS[version];
    // Remove version prefix for v3/v4
    let metricsStr = v;
    const prefixMatch = v.match(/^CVSS:\d\.\d\//);
    if (prefixMatch) {
      metricsStr = v.slice(prefixMatch[0].length);
    }

    const parts = metricsStr.split('/');
    const result: ParsedMetric[] = [];
    for (const part of parts) {
      const colonIdx = part.indexOf(':');
      if (colonIdx === -1) continue;
      const key = part.slice(0, colonIdx);
      const value = part.slice(colonIdx + 1);
      const definition = definitions[key];
      const metricValue = definition?.values[value];

      result.push({
        key,
        value,
        definition,
        valueLabel: metricValue?.label,
        valueDescription: metricValue?.description,
      });
    }
    return result;
  });

  toggleExpanded(): void {
    this.expanded.update((v) => !v);
  }
}
