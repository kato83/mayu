import { Component, inject, input, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { EnvironmentProfileBinding, TriageProfile } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-environment-profile-binding',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="bg-white dark:bg-slate-800 rounded-lg shadow">
      <!-- Header -->
      <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@envProfileBinding.title">Triage Profile Configuration</h2>
      </div>

      <!-- Project Default Profile -->
      <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
        <label class="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-2" i18n="@@envProfileBinding.defaultProfileLabel">Project Default Profile</label>
        <div class="flex items-center gap-2">
          <select
            class="rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
            [ngModel]="defaultProfile()"
            (ngModelChange)="defaultProfile.set($event)">
            <option value="" i18n="@@envProfileBinding.noDefault">-- None --</option>
            @for (p of profiles(); track p.name) {
              <option [value]="p.name">{{ p.name }}</option>
            }
          </select>
          <button
            (click)="saveDefaultProfile()"
            [disabled]="savingDefault()"
            class="text-xs px-3 py-1.5 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
            i18n="@@envProfileBinding.saveDefault">Save</button>
          <button
            (click)="clearDefaultProfile()"
            [disabled]="savingDefault() || !defaultProfile()"
            class="text-xs px-3 py-1.5 rounded-md bg-slate-200 dark:bg-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-300 dark:hover:bg-slate-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
            i18n="@@envProfileBinding.clearDefault">Clear</button>
          @if (defaultStatusMessage()) {
            <span class="text-xs text-green-600 dark:text-green-400">{{ defaultStatusMessage() }}</span>
          }
        </div>
      </div>

      <!-- Environment Bindings Header -->
      <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
        <h3 class="text-xs font-semibold text-slate-600 dark:text-slate-300" i18n="@@envProfileBinding.bindingsTitle">Environment Bindings</h3>
        <button
          (click)="showForm.set(!showForm())"
          class="text-xs px-3 py-1.5 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition-colors cursor-pointer"
          i18n="@@envProfileBinding.addBinding">
          {{ showForm() ? 'Cancel' : '+ Add' }}
        </button>
      </div>

      <!-- Add Form -->
      @if (showForm()) {
        <div class="px-4 py-3 bg-slate-50 dark:bg-slate-700/30 border-b border-slate-200 dark:border-slate-700">
          <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div>
              <label class="block text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@envProfileBinding.environmentLabel">Environment</label>
              @if (useCustomEnv()) {
                <div class="flex gap-1">
                  <input
                    type="text"
                    class="flex-1 rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                    [ngModel]="formEnvironment()"
                    (ngModelChange)="formEnvironment.set($event)"
                    placeholder="custom" />
                  <button
                    (click)="useCustomEnv.set(false); formEnvironment.set('production')"
                    class="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 cursor-pointer"
                    title="Switch to dropdown">&#x2190;</button>
                </div>
              } @else {
                <div class="flex gap-1">
                  <select
                    class="flex-1 rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                    [ngModel]="formEnvironment()"
                    (ngModelChange)="formEnvironment.set($event)">
                    <option value="production">production</option>
                    <option value="staging">staging</option>
                    <option value="development">development</option>
                    <option value="qa">qa</option>
                    <option value="internal">internal</option>
                  </select>
                  <button
                    (click)="useCustomEnv.set(true); formEnvironment.set('')"
                    class="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 cursor-pointer"
                    i18n-title="@@envProfileBinding.customEnvTooltip"
                    title="Use custom environment name">...</button>
                </div>
              }
            </div>
            <div>
              <label class="block text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@envProfileBinding.profileLabel">Profile</label>
              <select
                class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                [ngModel]="formProfile()"
                (ngModelChange)="formProfile.set($event)">
                @for (p of profiles(); track p.name) {
                  <option [value]="p.name">{{ p.name }}</option>
                }
              </select>
            </div>
            <div>
              <label class="block text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@envProfileBinding.descriptionLabel">Description</label>
              <input
                type="text"
                class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                [ngModel]="formDescription()"
                (ngModelChange)="formDescription.set($event)"
                i18n-placeholder="@@envProfileBinding.descriptionPlaceholder"
                placeholder="Optional description" />
            </div>
            <div class="flex items-end">
              <button
                (click)="saveBinding()"
                [disabled]="!formEnvironment() || !formProfile()"
                class="w-full px-3 py-1.5 rounded-md text-sm font-medium bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
                i18n="@@envProfileBinding.saveBinding">Save</button>
            </div>
          </div>
        </div>
      }

      <!-- Bindings Table -->
      <div class="overflow-x-auto">
        <table class="w-full text-sm text-left">
          <thead>
            <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
              <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@envProfileBinding.colEnvironment">Environment</th>
              <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@envProfileBinding.colProfile">Profile</th>
              <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@envProfileBinding.colDescription">Description</th>
              <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@envProfileBinding.colActions">Actions</th>
            </tr>
          </thead>
          <tbody>
            @for (binding of bindings(); track binding.environment) {
              <tr class="border-b border-slate-100 dark:border-slate-700/50">
                <td class="px-4 py-2">
                  <span [class]="envBadgeClass(binding.environment)">{{ binding.environment }}</span>
                </td>
                <td class="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-200">{{ binding.profile_name }}</td>
                <td class="px-4 py-2 text-xs text-slate-500 dark:text-slate-400 max-w-xs truncate">{{ binding.description || '-' }}</td>
                <td class="px-4 py-2">
                  <button
                    (click)="deleteBinding(binding.environment)"
                    class="text-xs text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                    i18n="@@envProfileBinding.remove">Remove</button>
                </td>
              </tr>
            } @empty {
              <tr>
                <td colspan="4" class="px-4 py-6 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@envProfileBinding.noBindings">
                  No environment bindings configured. Add a binding to assign triage profiles per environment.
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>

      <!-- Status message -->
      @if (statusMessage()) {
        <div class="px-4 py-2 text-xs text-green-600 dark:text-green-400">{{ statusMessage() }}</div>
      }
    </div>
  `,
})
export class EnvironmentProfileBindingComponent implements OnInit {
  private readonly triageService = inject(TriageService);

  /** The project ID to manage bindings for */
  readonly projectId = input.required<number>();

  readonly bindings = signal<EnvironmentProfileBinding[]>([]);
  readonly profiles = signal<TriageProfile[]>([]);
  readonly showForm = signal(false);
  readonly statusMessage = signal<string>('');
  readonly defaultProfile = signal<string>('');
  readonly defaultStatusMessage = signal<string>('');
  readonly savingDefault = signal(false);

  // Form fields
  readonly formEnvironment = signal('production');
  readonly formProfile = signal('');
  readonly formDescription = signal('');
  readonly useCustomEnv = signal(false);

  ngOnInit(): void {
    this.loadBindings();
    this.loadProfiles();
    this.loadDefaultProfile();
  }

  private loadBindings(): void {
    this.triageService.listBindings(String(this.projectId())).subscribe({
      next: (b) => this.bindings.set(b),
      error: () => {},
    });
  }

  private loadProfiles(): void {
    this.triageService.listProfiles().subscribe({
      next: (p) => {
        this.profiles.set(p);
        if (p.length > 0 && !this.formProfile()) {
          this.formProfile.set(p[0].name);
        }
      },
      error: () => {},
    });
  }

  private loadDefaultProfile(): void {
    this.triageService.getDefaultProfile(String(this.projectId())).subscribe({
      next: (res) => {
        if (res?.profile_name) {
          this.defaultProfile.set(res.profile_name);
        }
      },
      error: () => {},
    });
  }

  saveDefaultProfile(): void {
    const profileName = this.defaultProfile();
    if (!profileName) return;

    this.savingDefault.set(true);
    this.triageService.setDefaultProfile(String(this.projectId()), profileName).subscribe({
      next: () => {
        this.savingDefault.set(false);
        this.showTemporaryMessage(
          'defaultStatusMessage',
          $localize`:@@envProfileBinding.defaultSaved:Default profile saved`,
        );
      },
      error: () => {
        this.savingDefault.set(false);
        this.showTemporaryMessage(
          'defaultStatusMessage',
          $localize`:@@envProfileBinding.defaultSaveError:Error saving default profile`,
        );
      },
    });
  }

  clearDefaultProfile(): void {
    this.savingDefault.set(true);
    this.triageService.clearDefaultProfile(String(this.projectId())).subscribe({
      next: () => {
        this.savingDefault.set(false);
        this.defaultProfile.set('');
        this.showTemporaryMessage(
          'defaultStatusMessage',
          $localize`:@@envProfileBinding.defaultCleared:Default profile cleared`,
        );
      },
      error: () => {
        this.savingDefault.set(false);
        this.showTemporaryMessage(
          'defaultStatusMessage',
          $localize`:@@envProfileBinding.defaultClearError:Error clearing default profile`,
        );
      },
    });
  }

  saveBinding(): void {
    const environment = this.formEnvironment();
    const profile = this.formProfile();
    if (!environment || !profile) return;

    this.triageService
      .setBinding(String(this.projectId()), environment, {
        profile_name: profile,
        description: this.formDescription() || undefined,
      })
      .subscribe({
        next: () => {
          this.showForm.set(false);
          this.formEnvironment.set('production');
          this.formDescription.set('');
          this.useCustomEnv.set(false);
          this.showTemporaryMessage('statusMessage', $localize`:@@envProfileBinding.bindingSaved:Binding saved`);
          this.loadBindings();
        },
        error: () => {
          this.showTemporaryMessage(
            'statusMessage',
            $localize`:@@envProfileBinding.bindingSaveError:Error saving binding`,
          );
        },
      });
  }

  deleteBinding(environment: string): void {
    this.triageService.deleteBinding(String(this.projectId()), environment).subscribe({
      next: () => {
        this.showTemporaryMessage('statusMessage', $localize`:@@envProfileBinding.bindingRemoved:Binding removed`);
        this.loadBindings();
      },
      error: () => {
        this.showTemporaryMessage(
          'statusMessage',
          $localize`:@@envProfileBinding.bindingRemoveError:Error removing binding`,
        );
      },
    });
  }

  envBadgeClass(env: string): string {
    const base = 'inline-block px-1.5 py-0.5 rounded text-xs font-medium';
    switch (env) {
      case 'production':
        return `${base} bg-red-50 text-red-600 dark:bg-red-900/20 dark:text-red-400`;
      case 'staging':
        return `${base} bg-amber-50 text-amber-600 dark:bg-amber-900/20 dark:text-amber-400`;
      case 'development':
        return `${base} bg-green-50 text-green-600 dark:bg-green-900/20 dark:text-green-400`;
      case 'qa':
        return `${base} bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400`;
      case 'internal':
        return `${base} bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300`;
      default:
        return `${base} bg-purple-50 text-purple-600 dark:bg-purple-900/20 dark:text-purple-400`;
    }
  }

  private showTemporaryMessage(field: 'statusMessage' | 'defaultStatusMessage', message: string): void {
    if (field === 'statusMessage') {
      this.statusMessage.set(message);
    } else {
      this.defaultStatusMessage.set(message);
    }
    setTimeout(() => {
      if (field === 'statusMessage') {
        this.statusMessage.set('');
      } else {
        this.defaultStatusMessage.set('');
      }
    }, 3000);
  }
}
