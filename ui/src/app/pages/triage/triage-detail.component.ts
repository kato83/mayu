import { DecimalPipe } from '@angular/common';
import { Component, inject, input, type OnChanges, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { PriorityLevel, TriageProfile, TriageResult } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';
import { ScoreBreakdownChartComponent } from './score-breakdown-chart.component';

/**
 * TriageDetailComponent is designed to be embedded within the vulnerability detail page.
 * It displays the triage analysis for a specific vulnerability including priority badge,
 * composite score, SSVC decision, rationale, and signal contribution chart.
 */
@Component({
  selector: 'app-triage-detail',
  standalone: true,
  imports: [DecimalPipe, FormsModule, ScoreBreakdownChartComponent],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-32">
        <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
      </div>
    } @else if (result()) {
      <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
        <!-- Header with priority badge and score -->
        <div class="flex items-center justify-between mb-4">
          <div class="flex items-center gap-3">
            <h3 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triageDetail.title">Triage Analysis</h3>
            <span [class]="priorityBadgeClass(result()!.priority_level)">{{ result()!.priority_level }}</span>
          </div>
          <div class="flex items-center gap-2">
            <label class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triageDetail.profileLabel">Profile:</label>
            <select
              class="rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-xs px-2 py-1 text-slate-900 dark:text-white"
              [ngModel]="selectedProfile()"
              (ngModelChange)="onProfileChange($event)">
              @for (p of profiles(); track p.name) {
                <option [value]="p.name">{{ p.name }}</option>
              }
            </select>
          </div>
        </div>

        <!-- Score & SSVC Info -->
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
          <div class="text-center p-3 bg-slate-50 dark:bg-slate-700/50 rounded">
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triageDetail.compositeScore">Composite Score</p>
            <p class="text-xl font-bold text-slate-900 dark:text-white mt-1">{{ (result()!.composite_score * 100) | number:'1.1-1' }}%</p>
          </div>
          <div class="text-center p-3 bg-slate-50 dark:bg-slate-700/50 rounded">
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triageDetail.ssvcDecision">SSVC Decision</p>
            <p class="text-lg font-semibold text-slate-900 dark:text-white mt-1">{{ result()!.ssvc_decision }}</p>
          </div>
          <div class="text-center p-3 bg-slate-50 dark:bg-slate-700/50 rounded">
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triageDetail.profile">Profile Used</p>
            <p class="text-lg font-semibold text-slate-900 dark:text-white mt-1">{{ result()!.profile_used }}</p>
          </div>
        </div>

        <!-- Rationale -->
        <div class="mb-4">
          <h4 class="text-xs font-semibold text-slate-600 dark:text-slate-300 mb-2" i18n="@@triageDetail.rationale">Rationale</h4>
          <p class="text-sm text-slate-700 dark:text-slate-300">{{ result()!.rationale?.summary }}</p>
          @if (result()!.rationale?.top_factors?.length) {
            <ul class="mt-2 space-y-1">
              @for (factor of result()!.rationale.top_factors; track factor.description) {
                <li class="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-2">
                  <span class="w-2 h-2 rounded-full bg-indigo-500"></span>
                  {{ factor.description }} ({{ factor.impact }})
                </li>
              }
            </ul>
          }
        </div>

        <!-- Signal Contribution Chart -->
        @if (result()!.rationale?.signal_details?.length) {
          <div>
            <h4 class="text-xs font-semibold text-slate-600 dark:text-slate-300 mb-2" i18n="@@triageDetail.signalBreakdown">Signal Contributions</h4>
            <app-score-breakdown-chart
              [signals]="result()!.rationale.signal_details"
              chartType="bar"
              height="180px" />
          </div>
        }
      </div>
    } @else {
      <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
        <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@triageDetail.noData">
          No triage data available for this vulnerability.
        </p>
      </div>
    }
  `,
})
export class TriageDetailComponent implements OnInit, OnChanges {
  private readonly triageService = inject(TriageService);

  /** The vulnerability ID to triage */
  readonly vulnerabilityId = input.required<string>();

  readonly loading = signal(true);
  readonly result = signal<TriageResult | null>(null);
  readonly profiles = signal<TriageProfile[]>([]);
  readonly selectedProfile = signal<string>('default');

  ngOnInit(): void {
    this.loadProfiles();
    this.loadTriage();
  }

  ngOnChanges(): void {
    this.loadTriage();
  }

  onProfileChange(profile: string): void {
    this.selectedProfile.set(profile);
    this.loadTriage();
  }

  private loadProfiles(): void {
    this.triageService.listProfiles().subscribe({
      next: (p) => this.profiles.set(p),
      error: () => {},
    });
  }

  private loadTriage(): void {
    this.loading.set(true);
    const profile = this.selectedProfile() !== 'default' ? this.selectedProfile() : undefined;
    this.triageService.getVulnerabilityTriage(this.vulnerabilityId(), profile).subscribe({
      next: (r) => {
        this.result.set(r);
        this.loading.set(false);
      },
      error: () => {
        this.result.set(null);
        this.loading.set(false);
      },
    });
  }

  priorityBadgeClass(level: PriorityLevel): string {
    const base = 'inline-block px-2 py-0.5 rounded text-xs font-semibold';
    switch (level) {
      case 'Critical':
        return `${base} bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400`;
      case 'High':
        return `${base} bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400`;
      case 'Medium':
        return `${base} bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400`;
      case 'Low':
        return `${base} bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400`;
      default:
        return `${base} bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300`;
    }
  }

  hasSignalValues(): boolean {
    const sv = this.result()?.signal_values;
    return sv != null && Object.keys(sv).length > 0;
  }
}
