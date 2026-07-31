import { DecimalPipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { ExtendedWeights, Thresholds, TriageProfile } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-triage-profiles',
  standalone: true,
  imports: [DecimalPipe, FormsModule, RouterLink],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else {
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-900 dark:text-white" i18n="@@triageProfiles.title">Triage Profiles</h1>
        <a routerLink="/triage"
           class="text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
           i18n="@@triageProfiles.backToDashboard">Back to Dashboard</a>
      </div>

      <!-- Profiles List -->
      <section class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        @for (profile of profiles(); track profile.name) {
          <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
            <h3 class="font-bold text-slate-900 dark:text-white text-sm mb-1">{{ profile.name }}</h3>
            <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">{{ profile.description }}</p>

            <!-- Weights grid -->
            <div class="mb-2">
              <p class="text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" i18n="@@triageProfiles.weights">Weights</p>
              <div class="grid grid-cols-4 gap-1 text-xs">
                <span class="text-slate-500 dark:text-slate-400">cvss: {{ profile.weights.cvss | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">epss: {{ profile.weights.epss | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">lev: {{ profile.weights.lev | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">kev: {{ profile.weights.kev | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">patch: {{ profile.weights.patch | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">age: {{ profile.weights.age | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">exploit_db: {{ profile.weights.exploit_db | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">reachability: {{ profile.weights.reachability | number:'1.2-2' }}</span>
              </div>
            </div>

            <!-- Thresholds -->
            <div>
              <p class="text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" i18n="@@triageProfiles.thresholds">Thresholds</p>
              <div class="flex gap-3 text-xs">
                <span class="text-red-600 dark:text-red-400">critical: {{ profile.thresholds.critical | number:'1.2-2' }}</span>
                <span class="text-orange-600 dark:text-orange-400">high: {{ profile.thresholds.high | number:'1.2-2' }}</span>
                <span class="text-yellow-600 dark:text-yellow-400">medium: {{ profile.thresholds.medium | number:'1.2-2' }}</span>
              </div>
            </div>
          </div>
        } @empty {
          <div class="col-span-2 text-center text-sm text-slate-500 dark:text-slate-400 py-8" i18n="@@triageProfiles.noProfiles">
            No profiles available.
          </div>
        }
      </section>

      <!-- Create Custom Profile Toggle -->
      <div class="mb-4">
        <button
          type="button"
          class="px-4 py-2 rounded-md text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          (click)="showCreateForm.set(!showCreateForm())"
          i18n="@@triageProfiles.createBtn">
          {{ showCreateForm() ? 'Cancel' : 'Create Custom Profile' }}
        </button>
      </div>

      <!-- Create Custom Profile Form -->
      @if (showCreateForm()) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 mb-6">
          <h2 class="text-lg font-bold text-slate-900 dark:text-white mb-4" i18n="@@triageProfiles.createTitle">Create Custom Profile</h2>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <!-- Name -->
            <div>
              <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" i18n="@@triageProfiles.nameLabel">Name</label>
              <input type="text"
                     class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
                     [ngModel]="formName()"
                     (ngModelChange)="formName.set($event)"
                     placeholder="my-custom-profile" />
            </div>

            <!-- Description -->
            <div>
              <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" i18n="@@triageProfiles.descLabel">Description</label>
              <input type="text"
                     class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
                     [ngModel]="formDescription()"
                     (ngModelChange)="formDescription.set($event)"
                     placeholder="A custom triage profile" />
            </div>
          </div>

          <!-- Base Template Selector -->
          <div class="mb-4">
            <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" i18n="@@triageProfiles.baseLabel">Base Template</label>
            <select
              class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
              [ngModel]="formBase()"
              (ngModelChange)="onBaseChange($event)">
              <option value="" i18n="@@triageProfiles.selectBase">-- Select a base template --</option>
              @for (p of profiles(); track p.name) {
                <option [value]="p.name">{{ p.name }}</option>
              }
            </select>
          </div>

          <!-- Weights -->
          <div class="mb-4">
            <p class="text-sm font-medium text-slate-700 dark:text-slate-200 mb-2" i18n="@@triageProfiles.weightsSection">Weights</p>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">cvss</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().cvss"
                       (ngModelChange)="updateWeight('cvss', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">epss</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().epss"
                       (ngModelChange)="updateWeight('epss', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">lev</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().lev"
                       (ngModelChange)="updateWeight('lev', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">kev</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().kev"
                       (ngModelChange)="updateWeight('kev', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">patch</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().patch"
                       (ngModelChange)="updateWeight('patch', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">age</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().age"
                       (ngModelChange)="updateWeight('age', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">exploit_db</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().exploit_db"
                       (ngModelChange)="updateWeight('exploit_db', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">reachability</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().reachability"
                       (ngModelChange)="updateWeight('reachability', $event)" />
              </div>
            </div>
          </div>

          <!-- Thresholds -->
          <div class="mb-4">
            <p class="text-sm font-medium text-slate-700 dark:text-slate-200 mb-2" i18n="@@triageProfiles.thresholdsSection">Thresholds</p>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">critical</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formThresholds().critical"
                       (ngModelChange)="updateThreshold('critical', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">high</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formThresholds().high"
                       (ngModelChange)="updateThreshold('high', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">medium</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formThresholds().medium"
                       (ngModelChange)="updateThreshold('medium', $event)" />
              </div>
            </div>
          </div>

          <!-- Validate Button -->
          <div class="flex items-center gap-3 mb-3">
            <button
              type="button"
              class="px-4 py-2 rounded-md text-sm font-medium bg-green-600 text-white hover:bg-green-700 transition-colors disabled:opacity-50"
              [disabled]="validating() || !formName()"
              (click)="onValidate()"
              i18n="@@triageProfiles.validateBtn">
              Validate
            </button>
            @if (validating()) {
              <span class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triageProfiles.validating">Validating...</span>
            }
          </div>

          <!-- Validation Result -->
          @if (validationResult()) {
            @if (validationResult()!.valid) {
              <div class="rounded-md bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 text-sm text-green-700 dark:text-green-300" i18n="@@triageProfiles.validSuccess">
                Profile is valid.
              </div>
            } @else {
              <div class="rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3">
                <p class="text-sm font-medium text-red-700 dark:text-red-300 mb-1" i18n="@@triageProfiles.validErrors">Validation errors:</p>
                <ul class="list-disc list-inside text-xs text-red-600 dark:text-red-400">
                  @for (err of validationResult()!.errors; track err) {
                    <li>{{ err }}</li>
                  }
                </ul>
              </div>
            }
          }

          <!-- Note -->
          <p class="mt-4 text-xs text-slate-500 dark:text-slate-400 italic" i18n="@@triageProfiles.persistenceNote">
            Custom profiles are validated locally. Server-side persistence coming soon.
          </p>
        </section>
      }
    }
  `,
})
export class TriageProfilesComponent implements OnInit {
  private readonly triageService = inject(TriageService);

  readonly profiles = signal<TriageProfile[]>([]);
  readonly loading = signal(true);
  readonly showCreateForm = signal(false);

  readonly formName = signal('');
  readonly formDescription = signal('');
  readonly formBase = signal('');
  readonly formWeights = signal<ExtendedWeights>({
    cvss: 0,
    epss: 0,
    lev: 0,
    kev: 0,
    patch: 0,
    age: 0,
    exploit_db: 0,
    reachability: 0,
  });
  readonly formThresholds = signal<Thresholds>({
    critical: 0,
    high: 0,
    medium: 0,
  });

  readonly validating = signal(false);
  readonly validationResult = signal<{ valid: boolean; errors: string[] } | null>(null);

  ngOnInit(): void {
    this.triageService.listProfiles().subscribe({
      next: (profiles) => {
        this.profiles.set(profiles);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  onBaseChange(baseName: string): void {
    this.formBase.set(baseName);
    const base = this.profiles().find((p) => p.name === baseName);
    if (base) {
      this.formWeights.set({ ...base.weights });
      this.formThresholds.set({ ...base.thresholds });
    }
  }

  updateWeight(key: keyof ExtendedWeights, value: number): void {
    this.formWeights.set({ ...this.formWeights(), [key]: value });
  }

  updateThreshold(key: keyof Thresholds, value: number): void {
    this.formThresholds.set({ ...this.formThresholds(), [key]: value });
  }

  onValidate(): void {
    this.validating.set(true);
    this.validationResult.set(null);

    const profile: TriageProfile = {
      name: this.formName(),
      description: this.formDescription(),
      base: this.formBase(),
      weights: this.formWeights(),
      thresholds: this.formThresholds(),
    };

    this.triageService.validateProfile(profile).subscribe({
      next: (result) => {
        this.validationResult.set(result);
        this.validating.set(false);
      },
      error: (err) => {
        this.validationResult.set({
          valid: false,
          errors: [err?.error?.message || 'Validation request failed'],
        });
        this.validating.set(false);
      },
    });
  }
}
