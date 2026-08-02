import { DecimalPipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { ExtendedWeights, Thresholds, TriageProfile } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-triage-profiles',
  standalone: true,
  imports: [DecimalPipe, FormsModule],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else {
      <!-- Profiles List -->
      <section class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        @for (profile of profiles(); track profile.name) {
          <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 relative">
            <!-- Builtin badge or action buttons -->
            <div class="absolute top-3 right-3 flex items-center gap-2">
              @if (profile.builtin) {
                <span class="text-xs bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 px-2 py-0.5 rounded" i18n="@@triageProfiles.builtinBadge">Built-in</span>
              } @else {
                <button
                  type="button"
                  class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                  (click)="onEdit(profile)"
                  i18n="@@triageProfiles.editBtn">Edit</button>
                <button
                  type="button"
                  class="text-xs text-red-600 dark:text-red-400 hover:underline"
                  (click)="onDelete(profile)"
                  i18n="@@triageProfiles.deleteBtn">Delete</button>
              }
            </div>

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
                <span class="text-slate-500 dark:text-slate-400">exploit_db: {{ profile.weights.exploitdb | number:'1.2-2' }}</span>
                <span class="text-slate-500 dark:text-slate-400">exploitability: {{ profile.weights.exploitability | number:'1.2-2' }}</span>
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

      <!-- Create / Edit Form Toggle -->
      <div class="mb-4">
        <button
          type="button"
          class="px-4 py-2 rounded-md text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          (click)="toggleForm()"
          i18n="@@triageProfiles.createBtn">
          {{ showForm() ? 'Cancel' : (editingProfile() ? 'Cancel Edit' : 'Create Custom Profile') }}
        </button>
      </div>

      <!-- Create / Edit Form -->
      @if (showForm()) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 mb-6">
          <h2 class="text-lg font-bold text-slate-900 dark:text-white mb-4">
            @if (editingProfile()) {
              <span i18n="@@triageProfiles.editTitle">Edit Profile</span>
            } @else {
              <span i18n="@@triageProfiles.createTitle">Create Custom Profile</span>
            }
          </h2>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <!-- Name -->
            <div>
              <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" i18n="@@triageProfiles.nameLabel">Name</label>
              <input type="text"
                     class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white disabled:opacity-50"
                     [ngModel]="formName()"
                     (ngModelChange)="formName.set($event)"
                     [disabled]="!!editingProfile()"
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
              @for (p of builtinProfiles(); track p.name) {
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
                       [ngModel]="formWeights().exploitdb"
                       (ngModelChange)="updateWeight('exploitdb', $event)" />
              </div>
              <div>
                <label class="block text-xs text-slate-500 dark:text-slate-400 mb-0.5">exploitability</label>
                <input type="number" step="0.01" min="0" max="1"
                       class="w-full rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1 text-slate-900 dark:text-white"
                       [ngModel]="formWeights().exploitability"
                       (ngModelChange)="updateWeight('exploitability', $event)" />
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

          <!-- Action Buttons -->
          <div class="flex items-center gap-3 mb-3">
            <button
              type="button"
              class="px-4 py-2 rounded-md text-sm font-medium bg-green-600 text-white hover:bg-green-700 transition-colors disabled:opacity-50"
              [disabled]="saving() || !formName()"
              (click)="onSave()"
              i18n="@@triageProfiles.saveBtn">
              {{ editingProfile() ? 'Update' : 'Save' }}
            </button>
            @if (saving()) {
              <span class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triageProfiles.saving">Saving...</span>
            }
          </div>

          <!-- Validation/Save Result -->
          @if (saveResult()) {
            @if (saveResult()!.success) {
              <div class="rounded-md bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 text-sm text-green-700 dark:text-green-300">
                {{ saveResult()!.message }}
              </div>
            } @else {
              <div class="rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3">
                <p class="text-sm font-medium text-red-700 dark:text-red-300 mb-1" i18n="@@triageProfiles.validErrors">Errors:</p>
                <ul class="list-disc list-inside text-xs text-red-600 dark:text-red-400">
                  @for (err of saveResult()!.errors; track err) {
                    <li>{{ err }}</li>
                  }
                </ul>
              </div>
            }
          }
        </section>
      }

      <!-- Delete Confirmation -->
      @if (deletingProfile()) {
        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div class="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
            <h3 class="text-lg font-bold text-slate-900 dark:text-white mb-2" i18n="@@triageProfiles.deleteConfirmTitle">Delete Profile</h3>
            <p class="text-sm text-slate-600 dark:text-slate-400 mb-4">
              <span i18n="@@triageProfiles.deleteConfirmMsg">Are you sure you want to delete the profile</span>
              <strong class="ml-1">{{ deletingProfile()!.name }}</strong>?
            </p>
            <div class="flex gap-3 justify-end">
              <button
                type="button"
                class="px-4 py-2 rounded-md text-sm font-medium border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
                (click)="deletingProfile.set(null)"
                i18n="@@triageProfiles.cancelBtn">Cancel</button>
              <button
                type="button"
                class="px-4 py-2 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700"
                (click)="confirmDelete()"
                i18n="@@triageProfiles.confirmDeleteBtn">Delete</button>
            </div>
          </div>
        </div>
      }
    }
  `,
})
export class TriageProfilesComponent implements OnInit {
  private readonly triageService = inject(TriageService);

  readonly profiles = signal<TriageProfile[]>([]);
  readonly loading = signal(true);
  readonly showForm = signal(false);
  readonly editingProfile = signal<TriageProfile | null>(null);
  readonly deletingProfile = signal<TriageProfile | null>(null);

  readonly formName = signal('');
  readonly formDescription = signal('');
  readonly formBase = signal('');
  readonly formWeights = signal<ExtendedWeights>({
    cvss: 0.2,
    epss: 0.2,
    lev: 0.15,
    kev: 0.15,
    patch: 0.08,
    age: 0.05,
    exploitdb: 0.1,
    exploitability: 0.07,
  });
  readonly formThresholds = signal<Thresholds>({
    critical: 0.85,
    high: 0.65,
    medium: 0.4,
  });

  readonly saving = signal(false);
  readonly saveResult = signal<{ success: boolean; message: string; errors: string[] } | null>(null);

  ngOnInit(): void {
    this.loadProfiles();
  }

  get builtinProfiles(): () => TriageProfile[] {
    return () => this.profiles().filter((p) => p.builtin);
  }

  toggleForm(): void {
    if (this.showForm()) {
      this.showForm.set(false);
      this.editingProfile.set(null);
      this.resetForm();
    } else {
      this.showForm.set(true);
    }
  }

  onEdit(profile: TriageProfile): void {
    this.editingProfile.set(profile);
    this.formName.set(profile.name);
    this.formDescription.set(profile.description);
    this.formBase.set(profile.base ?? '');
    this.formWeights.set({ ...profile.weights });
    this.formThresholds.set({ ...profile.thresholds });
    this.showForm.set(true);
    this.saveResult.set(null);
  }

  onDelete(profile: TriageProfile): void {
    this.deletingProfile.set(profile);
  }

  confirmDelete(): void {
    const profile = this.deletingProfile();
    if (!profile) return;

    this.triageService.deleteProfile(profile.name).subscribe({
      next: () => {
        this.deletingProfile.set(null);
        this.loadProfiles();
      },
      error: (err) => {
        this.deletingProfile.set(null);
        this.saveResult.set({
          success: false,
          message: '',
          errors: [err?.error?.message || 'Failed to delete profile'],
        });
      },
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

  onSave(): void {
    this.saving.set(true);
    this.saveResult.set(null);

    const payload = {
      name: this.formName(),
      description: this.formDescription(),
      base: this.formBase() || undefined,
      weights: this.formWeights(),
      thresholds: this.formThresholds(),
    };

    const editing = this.editingProfile();

    if (editing) {
      // Update
      this.triageService.updateProfile(editing.name, payload).subscribe({
        next: () => {
          this.saveResult.set({
            success: true,
            message: $localize`:@@triageProfiles.updateSuccess:Profile updated successfully.`,
            errors: [],
          });
          this.saving.set(false);
          this.loadProfiles();
        },
        error: (err) => {
          this.handleSaveError(err);
        },
      });
    } else {
      // Create
      this.triageService.createProfile(payload as TriageProfile).subscribe({
        next: () => {
          this.saveResult.set({
            success: true,
            message: $localize`:@@triageProfiles.createSuccess:Profile created successfully.`,
            errors: [],
          });
          this.saving.set(false);
          this.loadProfiles();
          this.resetForm();
        },
        error: (err) => {
          this.handleSaveError(err);
        },
      });
    }
  }

  private handleSaveError(err: { error?: { errors?: string[]; message?: string } }): void {
    const errors = err?.error?.errors ?? [err?.error?.message ?? 'Save failed'];
    this.saveResult.set({ success: false, message: '', errors });
    this.saving.set(false);
  }

  private loadProfiles(): void {
    this.triageService.listProfiles().subscribe({
      next: (profiles) => {
        this.profiles.set(profiles);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  private resetForm(): void {
    this.formName.set('');
    this.formDescription.set('');
    this.formBase.set('');
    this.formWeights.set({
      cvss: 0.2,
      epss: 0.2,
      lev: 0.15,
      kev: 0.15,
      patch: 0.08,
      age: 0.05,
      exploitdb: 0.1,
      exploitability: 0.07,
    });
    this.formThresholds.set({
      critical: 0.85,
      high: 0.65,
      medium: 0.4,
    });
    this.editingProfile.set(null);
    this.saveResult.set(null);
  }
}
