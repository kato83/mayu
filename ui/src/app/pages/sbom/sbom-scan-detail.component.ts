import { DatePipe } from '@angular/common';
import { Component, computed, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import type { FindingStatusEntry, SBOMScanResult, ScanDiff, ScanFinding } from '../../models/sbom.model';
import { SbomService } from '../../services/sbom.service';

/** All valid finding statuses. */
const ALL_STATUSES = ['open', 'in_triage', 'suppressed', 'false_positive', 'risk_accepted', 'resolved'] as const;

@Component({
  selector: 'app-sbom-scan-detail',
  standalone: true,
  imports: [DatePipe, RouterLink, FormsModule],
  template: `
    <div>
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
          <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
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
            <div class="p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@sbom.scan.suppressedCount">Suppressed / False Positive</p>
              <p class="text-2xl font-bold text-amber-600 dark:text-amber-400">
                {{ suppressedCount() }}
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

          <!-- Status filter controls -->
          <div class="flex flex-wrap gap-2 mb-4">
            <span class="text-sm text-slate-500 dark:text-slate-400 self-center mr-2" i18n="@@sbom.scan.filterByStatus">Filter by status:</span>
            @for (status of allStatuses; track status) {
              <button
                (click)="toggleStatusFilter(status)"
                [class]="statusFilterClass(status)"
                type="button"
              >
                {{ statusLabel(status) }}
              </button>
            }
          </div>

          @if (filteredFindings().length === 0) {
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
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.findingStatus">Status</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.note">Note</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.scan.col.summary">Summary</th>
                  </tr>
                </thead>
                <tbody>
                  @for (finding of filteredFindings(); track finding.vuln_id + finding.purl) {
                    <tr class="border-b border-slate-200 dark:border-slate-700" [class]="findingRowClass(finding)">
                      <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ finding.name }}</td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ finding.version }}</td>
                      <td class="px-4 py-3">
                        <a [routerLink]="['/vulnerabilities', finding.vuln_id]" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:underline">{{ finding.vuln_id }}</a>
                      </td>
                      <td class="px-4 py-3">
                        <span [class]="severityClass(finding.severity)">{{ finding.severity }}</span>
                      </td>
                      <td class="px-4 py-3">
                        <select
                          [value]="getFindingStatus(finding)"
                          (change)="onStatusChange(finding, $event)"
                          class="text-xs border border-slate-300 dark:border-slate-600 rounded px-2 py-1 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                          [class]="statusSelectClass(getFindingStatus(finding))"
                        >
                          @for (status of allStatuses; track status) {
                            <option [value]="status" [selected]="status === getFindingStatus(finding)" [class]="statusOptionClass(status)">
                              {{ statusLabel(status) }}
                            </option>
                          }
                        </select>
                      </td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400 max-w-xs">
                        @if (getFindingJustification(finding)) {
                          <span class="inline-block max-w-[200px] truncate" [title]="getFindingJustification(finding)!">{{ getFindingJustification(finding) }}</span>
                        }
                      </td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400 max-w-xs truncate">{{ finding.summary }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </div>

        <!-- Justification Modal -->
        @if (showJustificationModal()) {
          <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" (click)="cancelStatusChange()">
            <div class="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 w-full max-w-md" (click)="$event.stopPropagation()">
              <h3 class="text-lg font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.scan.justificationTitle">
                Justification Required
              </h3>
              <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" i18n="@@sbom.scan.justificationDescription">
                Please provide a justification for accepting this risk.
              </p>
              <textarea
                [(ngModel)]="justificationText"
                class="w-full border border-slate-300 dark:border-slate-600 rounded-lg p-3 text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white resize-none"
                rows="4"
                [attr.placeholder]="justificationPlaceholder"
                i18n-placeholder="@@sbom.scan.justificationPlaceholder"
              ></textarea>
              @if (justificationRequired() && !justificationText.trim()) {
                <p class="text-red-500 text-xs mt-1" i18n="@@sbom.scan.justificationRequiredError">
                  Justification is required for this status.
                </p>
              }
              <div class="flex justify-end gap-3 mt-4">
                <button
                  (click)="cancelStatusChange()"
                  class="px-4 py-2 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200"
                  type="button"
                  i18n="@@sbom.scan.cancel"
                >
                  Cancel
                </button>
                <button
                  (click)="confirmStatusChange()"
                  [disabled]="justificationRequired() && !justificationText.trim()"
                  class="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  type="button"
                  i18n="@@sbom.scan.confirm"
                >
                  Confirm
                </button>
              </div>
            </div>
          </div>
        }

        <!-- Error notification -->
        @if (statusUpdateError()) {
          <div class="fixed bottom-4 right-4 z-50 bg-red-100 dark:bg-red-900/30 border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 px-4 py-3 rounded-lg shadow-lg" role="alert">
            <p class="text-sm">{{ statusUpdateError() }}</p>
          </div>
        }
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
  readonly findingStatuses = signal<Map<string, FindingStatusEntry>>(new Map());
  readonly activeStatusFilters = signal<Set<string>>(new Set(['open', 'in_triage']));
  readonly showJustificationModal = signal(false);
  readonly statusUpdateError = signal<string | null>(null);

  readonly allStatuses = ALL_STATUSES;
  justificationText = '';
  justificationPlaceholder = $localize`:@@sbom.scan.justificationPlaceholder:Enter justification...`;

  private pendingStatusChange: { finding: ScanFinding; newStatus: string } | null = null;

  projectId = 0;
  scanId = 0;

  /** Count of findings with suppressed or false_positive status. */
  readonly suppressedCount = computed(() => {
    const statuses = this.findingStatuses();
    let count = 0;
    statuses.forEach((entry) => {
      if (entry.status === 'suppressed' || entry.status === 'false_positive') {
        count++;
      }
    });
    return count;
  });

  /** Whether justification is required for the pending status change. */
  readonly justificationRequired = computed(() => {
    return this.pendingStatusChange?.newStatus === 'risk_accepted';
  });

  /** Findings filtered by the active status filters. */
  readonly filteredFindings = computed(() => {
    const result = this.scanResult();
    if (!result) return [];
    const filters = this.activeStatusFilters();
    const statuses = this.findingStatuses();
    return result.findings.filter((finding) => {
      const key = this.findingKey(finding);
      const entry = statuses.get(key);
      const currentStatus = entry ? entry.status : 'open';
      return filters.has(currentStatus);
    });
  });

  ngOnInit(): void {
    this.projectId = Number(this.route.snapshot.paramMap.get('projectId'));
    this.scanId = Number(this.route.snapshot.paramMap.get('scanId'));
    this.loadScanResult();
    this.loadDiff();
    this.loadFindingStatuses();
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

  private loadFindingStatuses(): void {
    this.sbomService.listFindingStatuses(this.scanId).subscribe({
      next: (entries) => {
        const map = new Map<string, FindingStatusEntry>();
        for (const entry of entries) {
          const key = `${entry.vuln_id}:${entry.purl}`;
          map.set(key, entry);
        }
        this.findingStatuses.set(map);
      },
    });
  }

  /** Toggle a status in the active filter set. */
  toggleStatusFilter(status: string): void {
    const current = new Set(this.activeStatusFilters());
    if (current.has(status)) {
      current.delete(status);
    } else {
      current.add(status);
    }
    this.activeStatusFilters.set(current);
  }

  /** Get the current status of a finding. */
  getFindingStatus(finding: ScanFinding): string {
    const key = this.findingKey(finding);
    const entry = this.findingStatuses().get(key);
    return entry ? entry.status : 'open';
  }

  /** Get the justification (note/memo) of a finding. */
  getFindingJustification(finding: ScanFinding): string | undefined {
    const key = this.findingKey(finding);
    const entry = this.findingStatuses().get(key);
    return entry?.justification;
  }

  /** Handle status dropdown change. */
  onStatusChange(finding: ScanFinding, event: Event): void {
    const select = event.target as HTMLSelectElement;
    const newStatus = select.value;
    const currentStatus = this.getFindingStatus(finding);

    if (newStatus === currentStatus) return;

    if (newStatus === 'risk_accepted') {
      // Show justification modal (required)
      this.pendingStatusChange = { finding, newStatus };
      this.justificationText = '';
      this.showJustificationModal.set(true);
    } else {
      // For other statuses, show modal for optional justification
      this.pendingStatusChange = { finding, newStatus };
      this.justificationText = '';
      this.showJustificationModal.set(true);
    }
  }

  /** Cancel the pending status change. */
  cancelStatusChange(): void {
    this.pendingStatusChange = null;
    this.justificationText = '';
    this.showJustificationModal.set(false);
  }

  /** Confirm and persist the status change. */
  confirmStatusChange(): void {
    if (!this.pendingStatusChange) return;

    const { finding, newStatus } = this.pendingStatusChange;
    const justification = this.justificationText.trim() || undefined;

    if (newStatus === 'risk_accepted' && !justification) return;

    this.showJustificationModal.set(false);
    this.pendingStatusChange = null;
    this.justificationText = '';

    this.sbomService
      .updateFindingStatus(this.scanId, finding.vuln_id, {
        status: newStatus,
        justification,
        purl: finding.purl,
      })
      .subscribe({
        next: (entry) => {
          const map = new Map(this.findingStatuses());
          const key = this.findingKey(finding);
          map.set(key, entry);
          this.findingStatuses.set(map);
        },
        error: () => {
          this.statusUpdateError.set(
            $localize`:@@sbom.scan.statusUpdateError:Failed to update finding status. Please try again.`,
          );
          setTimeout(() => this.statusUpdateError.set(null), 5000);
        },
      });
  }

  /** Get a human-readable label for a status value. */
  statusLabel(status: string): string {
    switch (status) {
      case 'open':
        return $localize`:@@sbom.scan.status.open:Open`;
      case 'in_triage':
        return $localize`:@@sbom.scan.status.inTriage:In Triage`;
      case 'suppressed':
        return $localize`:@@sbom.scan.status.suppressed:Suppressed`;
      case 'false_positive':
        return $localize`:@@sbom.scan.status.falsePositive:False Positive`;
      case 'risk_accepted':
        return $localize`:@@sbom.scan.status.riskAccepted:Risk Accepted`;
      case 'resolved':
        return $localize`:@@sbom.scan.status.resolved:Resolved`;
      default:
        return status;
    }
  }

  /** CSS class for the status filter button. */
  statusFilterClass(status: string): string {
    const isActive = this.activeStatusFilters().has(status);
    const base = 'px-3 py-1 text-xs font-medium rounded-full border transition-colors';
    if (isActive) {
      if (status === 'suppressed' || status === 'false_positive') {
        return `${base} bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700`;
      }
      return `${base} bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-700`;
    }
    return `${base} bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-600`;
  }

  /** CSS class for the status select dropdown based on current status. */
  statusSelectClass(status: string): string {
    if (status === 'suppressed' || status === 'false_positive') {
      return 'text-amber-700 dark:text-amber-300';
    }
    return '';
  }

  /** CSS class for status option elements. */
  statusOptionClass(status: string): string {
    if (status === 'suppressed' || status === 'false_positive') {
      return 'text-amber-700';
    }
    return '';
  }

  /** CSS class for a finding row based on its status. */
  findingRowClass(finding: ScanFinding): string {
    const status = this.getFindingStatus(finding);
    if (status === 'suppressed' || status === 'false_positive') {
      return 'opacity-60';
    }
    return '';
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

  private findingKey(finding: ScanFinding): string {
    return `${finding.vuln_id}:${finding.purl}`;
  }
}
