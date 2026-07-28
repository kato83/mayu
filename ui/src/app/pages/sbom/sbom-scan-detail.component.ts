import { Component, inject, signal, OnInit } from '@angular/core';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';

import { SbomService } from '../../services/sbom.service';
import { SBOMScanResult, ScanDiff, ScanFinding } from '../../models/sbom.model';

@Component({
  selector: 'app-sbom-scan-detail',
  standalone: true,
  imports: [DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <!-- Header -->
      <div class="flex items-center gap-4 mb-6">
        <a [routerLink]="['/sbom', projectId]" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300" i18n="@@sbom.scan.backToProject">
          &larr; Back to Project
        </a>
      </div>

      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.loading">Loading scan result...</p>
      } @else if (scanResult()) {
        <!-- Scan summary -->
        <div class="mb-8">
          <h1 class="text-2xl font-bold text-slate-900 dark:text-white mb-4" i18n="@@sbom.scan.title">
            Scan Result
          </h1>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.totalPackages">Total Packages</p>
              <p class="text-2xl font-bold text-slate-900 dark:text-white">{{ scanResult()!.total_packages }}</p>
            </div>
            <div class="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.vulnerablePackages">Vulnerable</p>
              <p class="text-2xl font-bold" [class]="scanResult()!.vulnerable_packages > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'">
                {{ scanResult()!.vulnerable_packages }}
              </p>
            </div>
            <div class="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.totalFindings">Total Findings</p>
              <p class="text-2xl font-bold text-slate-900 dark:text-white">{{ scanResult()!.total_findings }}</p>
            </div>
            <div class="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.status">Status</p>
              <p class="text-2xl font-bold" [class]="scanResult()!.status === 'completed' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'">
                {{ scanResult()!.status }}
              </p>
            </div>
          </div>
          <div class="mt-4 text-sm text-slate-500 dark:text-slate-400">
            <span i18n="@@sbom.scan.scannedAt">Scanned at:</span> {{ scanResult()!.scanned_at | date:'medium' }}
            &middot;
            <span i18n="@@sbom.scan.trigger">Trigger:</span> {{ scanResult()!.trigger }}
          </div>
        </div>

        <!-- Diff section -->
        @if (diff()) {
          <div class="mb-8">
            <h2 class="text-xl font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.scan.diffTitle">
              Changes from Previous Scan
            </h2>

            @if (diff()!.new_findings.length === 0 && diff()!.resolved_findings.length === 0) {
              <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.noDiff">
                No changes detected from the previous scan.
              </p>
            } @else {
              <!-- New findings -->
              @if (diff()!.new_findings.length > 0) {
                <div class="mb-4">
                  <h3 class="text-base font-medium text-red-600 dark:text-red-400 mb-2" i18n="@@sbom.scan.newFindings">
                    New Findings
                  </h3>
                  <div class="overflow-x-auto">
                    <table class="w-full text-sm text-left">
                      <thead class="text-xs uppercase bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">
                        <tr>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.package">Package</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.version">Version</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.vulnId">Vulnerability</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.severity">Severity</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.summary">Summary</th>
                        </tr>
                      </thead>
                      <tbody>
                        @for (finding of diff()!.new_findings; track finding.vuln_id + finding.purl) {
                          <tr class="border-b border-red-100 dark:border-red-900/30 bg-red-50/50 dark:bg-red-900/10">
                            <td class="px-4 py-2 text-slate-900 dark:text-white font-medium">{{ finding.name }}</td>
                            <td class="px-4 py-2 text-slate-600 dark:text-slate-400">{{ finding.version }}</td>
                            <td class="px-4 py-2">
                              <a [routerLink]="['/vulnerabilities', finding.vuln_id]" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:underline">{{ finding.vuln_id }}</a>
                            </td>
                            <td class="px-4 py-2">
                              <span [class]="severityClass(finding.severity)">{{ finding.severity }}</span>
                            </td>
                            <td class="px-4 py-2 text-slate-600 dark:text-slate-400 max-w-xs truncate">{{ finding.summary }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  </div>
                </div>
              }

              <!-- Resolved findings -->
              @if (diff()!.resolved_findings.length > 0) {
                <div class="mb-4">
                  <h3 class="text-base font-medium text-green-600 dark:text-green-400 mb-2" i18n="@@sbom.scan.resolvedFindings">
                    Resolved Findings
                  </h3>
                  <div class="overflow-x-auto">
                    <table class="w-full text-sm text-left">
                      <thead class="text-xs uppercase bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400">
                        <tr>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.package">Package</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.version">Version</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.vulnId">Vulnerability</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.severity">Severity</th>
                          <th class="px-4 py-2 whitespace-nowrap" i18n="@@sbom.scan.col.summary">Summary</th>
                        </tr>
                      </thead>
                      <tbody>
                        @for (finding of diff()!.resolved_findings; track finding.vuln_id + finding.purl) {
                          <tr class="border-b border-green-100 dark:border-green-900/30 bg-green-50/50 dark:bg-green-900/10">
                            <td class="px-4 py-2 text-slate-900 dark:text-white font-medium">{{ finding.name }}</td>
                            <td class="px-4 py-2 text-slate-600 dark:text-slate-400">{{ finding.version }}</td>
                            <td class="px-4 py-2">
                              <a [routerLink]="['/vulnerabilities', finding.vuln_id]" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:underline">{{ finding.vuln_id }}</a>
                            </td>
                            <td class="px-4 py-2">
                              <span [class]="severityClass(finding.severity)">{{ finding.severity }}</span>
                            </td>
                            <td class="px-4 py-2 text-slate-600 dark:text-slate-400 max-w-xs truncate">{{ finding.summary }}</td>
                          </tr>
                        }
                      </tbody>
                    </table>
                  </div>
                </div>
              }
            }
          </div>
        }

        <!-- All findings -->
        <div>
          <h2 class="text-xl font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.scan.findingsTitle">
            All Findings
          </h2>

          @if (scanResult()!.findings.length === 0) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.noFindings">
              No vulnerabilities found in this scan.
            </p>
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-sm text-left">
                <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                  <tr>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.package">Package</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.version">Version</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.vulnId">Vulnerability</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.severity">Severity</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.summary">Summary</th>
                  </tr>
                </thead>
                <tbody>
                  @for (finding of scanResult()!.findings; track finding.vuln_id + finding.purl) {
                    <tr class="border-b border-slate-200 dark:border-slate-700">
                      <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ finding.name }}</td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ finding.version }}</td>
                      <td class="px-4 py-3">
                        <a [routerLink]="['/vulnerabilities', finding.vuln_id]" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:underline">{{ finding.vuln_id }}</a>
                      </td>
                      <td class="px-4 py-3">
                        <span [class]="severityClass(finding.severity)">{{ finding.severity }}</span>
                      </td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400 max-w-xs truncate">{{ finding.summary }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </div>
      }
    </div>
  `,
})
export class SbomScanDetailComponent implements OnInit {
  private readonly sbomService = inject(SbomService);
  private readonly route = inject(ActivatedRoute);

  readonly scanResult = signal<SBOMScanResult | null>(null);
  readonly diff = signal<ScanDiff | null>(null);
  readonly loading = signal(true);

  projectId = 0;
  scanId = 0;

  ngOnInit(): void {
    this.projectId = Number(this.route.snapshot.paramMap.get('projectId'));
    this.scanId = Number(this.route.snapshot.paramMap.get('scanId'));
    this.loadScanResult();
    this.loadDiff();
  }

  private loadScanResult(): void {
    this.loading.set(true);
    this.sbomService.getScanResult(this.scanId).subscribe({
      next: (result) => {
        this.scanResult.set(result);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  private loadDiff(): void {
    this.sbomService.getScanDiff(this.scanId).subscribe({
      next: (diff) => this.diff.set(diff),
    });
  }

  severityClass(severity: string): string {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'px-2 py-0.5 rounded text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300';
      case 'HIGH':
        return 'px-2 py-0.5 rounded text-xs font-medium bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300';
      case 'MEDIUM':
        return 'px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300';
      case 'LOW':
        return 'px-2 py-0.5 rounded text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300';
      default:
        return 'px-2 py-0.5 rounded text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300';
    }
  }
}
