import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';

import { WatchlistService } from '../../services/watchlist.service';
import {
  Watchlist,
  WatchlistMatch,
  CreateWatchlistRequest,
  UpdateWatchlistRequest,
} from '../../models/watchlist.model';

@Component({
  selector: 'app-watchlists',
  standalone: true,
  imports: [FormsModule, DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white" i18n="@@watchlists.title">
          Watchlists
        </h1>
        <button
          (click)="onCreateNew()"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@watchlists.createButton"
        >
          Create Watchlist
        </button>
      </div>

      <!-- Create/Edit form -->
      @if (showForm()) {
        <div class="mb-6 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4">
            @if (editingId()) {
              <span i18n="@@watchlists.editTitle">Edit Watchlist</span>
            } @else {
              <span i18n="@@watchlists.createTitle">Create New Watchlist</span>
            }
          </h2>
          <form #watchlistForm="ngForm" (ngSubmit)="onSubmitForm()" class="space-y-4">
            <div>
              <label for="wlName" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.nameLabel">
                Name
              </label>
              <input
                id="wlName"
                type="text"
                [(ngModel)]="formName"
                name="wlName"
                required
                #wlNameCtrl="ngModel"
                class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                [class]="wlNameCtrl.invalid && (wlNameCtrl.dirty || wlNameCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                placeholder="e.g. My Go Packages"
                i18n-placeholder="@@watchlists.namePlaceholder"
              />
              @if (wlNameCtrl.invalid && (wlNameCtrl.dirty || wlNameCtrl.touched)) {
                <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@watchlists.nameRequired">Name is required.</p>
              }
            </div>

            <div>
              <label for="wlMatchType" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.matchTypeLabel">
                Match Type
              </label>
              <select
                id="wlMatchType"
                [(ngModel)]="formMatchType"
                name="wlMatchType"
                required
                #wlMatchTypeCtrl="ngModel"
                class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                [class]="wlMatchTypeCtrl.invalid && (wlMatchTypeCtrl.dirty || wlMatchTypeCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
              >
                <option value="package" i18n="@@watchlists.matchType.package">Package</option>
                <option value="purl" i18n="@@watchlists.matchType.purl">PURL</option>
                <option value="cpe" i18n="@@watchlists.matchType.cpe">CPE</option>
                <option value="ecosystem" i18n="@@watchlists.matchType.ecosystem">Ecosystem</option>
              </select>
              @if (wlMatchTypeCtrl.invalid && (wlMatchTypeCtrl.dirty || wlMatchTypeCtrl.touched)) {
                <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@watchlists.matchTypeRequired">Match type is required.</p>
              }
            </div>

            <!-- Conditional fields based on match type -->
            @if (formMatchType === 'package' || formMatchType === 'ecosystem') {
              <div>
                <label for="wlEcosystem" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.ecosystemLabel">
                  Ecosystem
                </label>
                <input
                  id="wlEcosystem"
                  type="text"
                  [(ngModel)]="formEcosystem"
                  name="wlEcosystem"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. Go, npm, PyPI"
                  i18n-placeholder="@@watchlists.ecosystemPlaceholder"
                />
              </div>
            }

            @if (formMatchType === 'package') {
              <div>
                <label for="wlPackageName" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.packageNameLabel">
                  Package Name
                </label>
                <input
                  id="wlPackageName"
                  type="text"
                  [(ngModel)]="formPackageName"
                  name="wlPackageName"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. golang.org/x/crypto"
                  i18n-placeholder="@@watchlists.packageNamePlaceholder"
                />
              </div>
            }

            @if (formMatchType === 'purl') {
              <div>
                <label for="wlPurlPattern" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.purlPatternLabel">
                  PURL Pattern
                </label>
                <input
                  id="wlPurlPattern"
                  type="text"
                  [(ngModel)]="formPurlPattern"
                  name="wlPurlPattern"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. pkg:golang/golang.org/x/crypto"
                  i18n-placeholder="@@watchlists.purlPatternPlaceholder"
                />
              </div>
            }

            @if (formMatchType === 'cpe') {
              <div>
                <label for="wlCpePattern" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.cpePatternLabel">
                  CPE Pattern
                </label>
                <input
                  id="wlCpePattern"
                  type="text"
                  [(ngModel)]="formCpePattern"
                  name="wlCpePattern"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. cpe:2.3:a:apache:http_server"
                  i18n-placeholder="@@watchlists.cpePatternPlaceholder"
                />
              </div>
            }

            <div>
              <label for="wlSeverityMin" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.severityMinLabel">
                Minimum Severity
              </label>
              <select
                id="wlSeverityMin"
                [(ngModel)]="formSeverityMin"
                name="wlSeverityMin"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="" i18n="@@watchlists.severity.any">Any</option>
                <option value="5" i18n="@@watchlists.severity.critical">Critical</option>
                <option value="4" i18n="@@watchlists.severity.high">High</option>
                <option value="3" i18n="@@watchlists.severity.medium">Medium</option>
                <option value="2" i18n="@@watchlists.severity.low">Low</option>
                <option value="1" i18n="@@watchlists.severity.none">None</option>
              </select>
            </div>

            <div>
              <label for="wlEpssThreshold" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@watchlists.epssThresholdLabel">
                EPSS Threshold
              </label>
              <input
                id="wlEpssThreshold"
                type="number"
                [(ngModel)]="formEpssThreshold"
                name="wlEpssThreshold"
                min="0"
                max="1"
                step="0.01"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="e.g. 0.5"
                i18n-placeholder="@@watchlists.epssThresholdPlaceholder"
              />
            </div>

            @if (editingId()) {
              <div class="flex items-center gap-2">
                <input
                  id="wlEnabled"
                  type="checkbox"
                  [(ngModel)]="formEnabled"
                  name="wlEnabled"
                  class="h-4 w-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500"
                />
                <label for="wlEnabled" class="text-sm font-medium text-slate-700 dark:text-slate-300" i18n="@@watchlists.enabledLabel">
                  Enabled
                </label>
              </div>
            }

            <div class="flex gap-2">
              <button
                type="submit"
                [disabled]="submitting() || watchlistForm.invalid"
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
                i18n="@@watchlists.submitButton"
              >
                Save
              </button>
              <button
                type="button"
                (click)="onCancelForm()"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@watchlists.cancelButton"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      }

      <!-- Watchlists table -->
      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@watchlists.loading">Loading...</p>
      } @else if (watchlists().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@watchlists.noWatchlists">
          No watchlists found. Create one to start monitoring vulnerabilities.
        </p>
      } @else {
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3" i18n="@@watchlists.col.name">Name</th>
                <th class="px-4 py-3" i18n="@@watchlists.col.type">Type</th>
                <th class="px-4 py-3" i18n="@@watchlists.col.conditions">Conditions</th>
                <th class="px-4 py-3" i18n="@@watchlists.col.enabled">Enabled</th>
                <th class="px-4 py-3" i18n="@@watchlists.col.created">Created</th>
                <th class="px-4 py-3" i18n="@@watchlists.col.actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (wl of watchlists(); track wl.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ wl.name }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">
                    <span class="px-2 py-0.5 rounded text-xs font-medium bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                      {{ wl.match_type }}
                    </span>
                  </td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400 text-xs">
                    {{ formatConditions(wl) }}
                  </td>
                  <td class="px-4 py-3">
                    @if (wl.enabled) {
                      <span class="text-green-600 dark:text-green-400" i18n="@@watchlists.yes">Yes</span>
                    } @else {
                      <span class="text-red-600 dark:text-red-400" i18n="@@watchlists.no">No</span>
                    }
                  </td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ wl.created_at | date:'short' }}</td>
                  <td class="px-4 py-3">
                    <div class="flex gap-2">
                      <button
                        (click)="onEdit(wl)"
                        class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium cursor-pointer"
                        i18n="@@watchlists.editButton"
                      >
                        Edit
                      </button>
                      <button
                        (click)="onDelete(wl)"
                        class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 font-medium cursor-pointer"
                        i18n="@@watchlists.deleteButton"
                      >
                        Delete
                      </button>
                      <button
                        (click)="onViewMatches(wl)"
                        class="text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300 font-medium cursor-pointer"
                        i18n="@@watchlists.matchesButton"
                      >
                        Matches
                      </button>
                    </div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      <!-- Match history section -->
      @if (showMatches()) {
        <div class="mt-8">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-slate-900 dark:text-white" i18n="@@watchlists.matchHistory">
              Match History
            </h2>
            <button
              (click)="showMatches.set(false)"
              class="text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 cursor-pointer"
              i18n="@@watchlists.closeMatches"
            >
              Close
            </button>
          </div>
          @if (matchesLoading()) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@watchlists.matchesLoading">Loading matches...</p>
          } @else if (matches().length === 0) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@watchlists.noMatches">
              No matches found for this watchlist.
            </p>
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-sm text-left">
                <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                  <tr>
                    <th class="px-4 py-3" i18n="@@watchlists.match.vulnId">Vulnerability ID</th>
                    <th class="px-4 py-3" i18n="@@watchlists.match.matchedAt">Matched At</th>
                    <th class="px-4 py-3" i18n="@@watchlists.match.notified">Notified</th>
                  </tr>
                </thead>
                <tbody>
                  @for (match of matches(); track match.id) {
                    <tr class="border-b border-slate-200 dark:border-slate-700">
                      <td class="px-4 py-3">
                        <a
                          [routerLink]="['/vulnerabilities', match.vulnerability_id]"
                          class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                        >
                          {{ match.vulnerability_id }}
                        </a>
                      </td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ match.matched_at | date:'short' }}</td>
                      <td class="px-4 py-3">
                        @if (match.notified) {
                          <span class="text-green-600 dark:text-green-400" i18n="@@watchlists.yes">Yes</span>
                        } @else {
                          <span class="text-slate-400 dark:text-slate-500" i18n="@@watchlists.no">No</span>
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            <p class="mt-2 text-xs text-slate-500 dark:text-slate-400">
              <span i18n="@@watchlists.matchTotal">Total matches:</span> {{ matchTotal() }}
            </p>
          }
        </div>
      }

      <!-- Delete confirmation -->
      @if (confirmDelete()) {
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div class="bg-white dark:bg-slate-800 rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <h3 class="text-lg font-semibold text-slate-900 dark:text-white mb-2" i18n="@@watchlists.deleteConfirmTitle">
              Delete Watchlist
            </h3>
            <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" i18n="@@watchlists.deleteConfirmMessage">
              Are you sure you want to delete this watchlist? This action cannot be undone.
            </p>
            <div class="flex gap-2 justify-end">
              <button
                (click)="confirmDelete.set(null)"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@watchlists.cancelButton"
              >
                Cancel
              </button>
              <button
                (click)="onConfirmDelete()"
                class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@watchlists.confirmDeleteButton"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      }
    </div>
  `,
})
export class WatchlistsComponent implements OnInit {
  private readonly watchlistService = inject(WatchlistService);

  readonly watchlists = signal<Watchlist[]>([]);
  readonly loading = signal(true);
  readonly submitting = signal(false);
  readonly showForm = signal(false);
  readonly editingId = signal<number | null>(null);
  readonly confirmDelete = signal<Watchlist | null>(null);

  // Match history
  readonly showMatches = signal(false);
  readonly matches = signal<WatchlistMatch[]>([]);
  readonly matchTotal = signal(0);
  readonly matchesLoading = signal(false);

  // Form fields
  formName = '';
  formMatchType: 'package' | 'purl' | 'cpe' | 'ecosystem' = 'package';
  formEcosystem = '';
  formPackageName = '';
  formPurlPattern = '';
  formCpePattern = '';
  formSeverityMin = '';
  formEpssThreshold: number | null = null;
  formEnabled = true;

  ngOnInit(): void {
    this.loadWatchlists();
  }

  private loadWatchlists(): void {
    this.loading.set(true);
    this.watchlistService.list().subscribe({
      next: (watchlists) => {
        this.watchlists.set(watchlists);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  onCreateNew(): void {
    this.resetForm();
    this.editingId.set(null);
    this.showForm.set(true);
  }

  onEdit(wl: Watchlist): void {
    this.editingId.set(wl.id);
    this.formName = wl.name;
    this.formMatchType = wl.match_type;
    this.formEcosystem = wl.ecosystem || '';
    this.formPackageName = wl.package_name || '';
    this.formPurlPattern = wl.purl_pattern || '';
    this.formCpePattern = wl.cpe_pattern || '';
    this.formSeverityMin = wl.severity_min != null ? wl.severity_min.toString() : '';
    this.formEpssThreshold = wl.epss_threshold ?? null;
    this.formEnabled = wl.enabled;
    this.showForm.set(true);
  }

  onCancelForm(): void {
    this.showForm.set(false);
    this.resetForm();
  }

  onSubmitForm(): void {
    if (!this.formName) return;

    this.submitting.set(true);

    if (this.editingId()) {
      const req: UpdateWatchlistRequest = this.buildUpdateRequest();
      this.watchlistService.update(this.editingId()!, req).subscribe({
        next: () => {
          this.showForm.set(false);
          this.submitting.set(false);
          this.resetForm();
          this.loadWatchlists();
        },
        error: () => {
          this.submitting.set(false);
        },
      });
    } else {
      const req: CreateWatchlistRequest = this.buildCreateRequest();
      this.watchlistService.create(req).subscribe({
        next: () => {
          this.showForm.set(false);
          this.submitting.set(false);
          this.resetForm();
          this.loadWatchlists();
        },
        error: () => {
          this.submitting.set(false);
        },
      });
    }
  }

  onDelete(wl: Watchlist): void {
    this.confirmDelete.set(wl);
  }

  onConfirmDelete(): void {
    const wl = this.confirmDelete();
    if (!wl) return;

    this.watchlistService.delete(wl.id).subscribe({
      next: () => {
        this.confirmDelete.set(null);
        this.loadWatchlists();
      },
    });
  }

  onViewMatches(wl: Watchlist): void {
    this.matchesLoading.set(true);
    this.showMatches.set(true);
    this.watchlistService.listMatches(wl.id, 20, 0).subscribe({
      next: (response) => {
        this.matches.set(response.matches);
        this.matchTotal.set(response.total);
        this.matchesLoading.set(false);
      },
      error: () => {
        this.matchesLoading.set(false);
      },
    });
  }

  formatConditions(wl: Watchlist): string {
    const parts: string[] = [];
    if (wl.ecosystem) parts.push(`ecosystem: ${wl.ecosystem}`);
    if (wl.package_name) parts.push(`package: ${wl.package_name}`);
    if (wl.purl_pattern) parts.push(`purl: ${wl.purl_pattern}`);
    if (wl.cpe_pattern) parts.push(`cpe: ${wl.cpe_pattern}`);
    if (wl.severity_min != null) parts.push(`severity >= ${this.severityLabel(wl.severity_min)}`);
    if (wl.epss_threshold != null) parts.push(`epss >= ${wl.epss_threshold}`);
    return parts.join(', ') || '-';
  }

  private severityLabel(value: number): string {
    switch (value) {
      case 5: return 'CRITICAL';
      case 4: return 'HIGH';
      case 3: return 'MEDIUM';
      case 2: return 'LOW';
      case 1: return 'NONE';
      default: return String(value);
    }
  }

  private resetForm(): void {
    this.formName = '';
    this.formMatchType = 'package';
    this.formEcosystem = '';
    this.formPackageName = '';
    this.formPurlPattern = '';
    this.formCpePattern = '';
    this.formSeverityMin = '';
    this.formEpssThreshold = null;
    this.formEnabled = true;
    this.editingId.set(null);
  }

  private buildCreateRequest(): CreateWatchlistRequest {
    const req: CreateWatchlistRequest = {
      name: this.formName,
      match_type: this.formMatchType,
    };
    if (this.formEcosystem) req.ecosystem = this.formEcosystem;
    if (this.formPackageName) req.package_name = this.formPackageName;
    if (this.formPurlPattern) req.purl_pattern = this.formPurlPattern;
    if (this.formCpePattern) req.cpe_pattern = this.formCpePattern;
    if (this.formSeverityMin) req.severity_min = parseInt(this.formSeverityMin, 10);
    if (this.formEpssThreshold != null) req.epss_threshold = this.formEpssThreshold;
    return req;
  }

  private buildUpdateRequest(): UpdateWatchlistRequest {
    const req: UpdateWatchlistRequest = {
      name: this.formName,
      match_type: this.formMatchType,
      enabled: this.formEnabled,
    };
    if (this.formEcosystem) req.ecosystem = this.formEcosystem;
    if (this.formPackageName) req.package_name = this.formPackageName;
    if (this.formPurlPattern) req.purl_pattern = this.formPurlPattern;
    if (this.formCpePattern) req.cpe_pattern = this.formCpePattern;
    if (this.formSeverityMin) req.severity_min = parseInt(this.formSeverityMin, 10);
    if (this.formEpssThreshold != null) req.epss_threshold = this.formEpssThreshold;
    return req;
  }
}
