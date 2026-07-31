import { Component, inject, input, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { ServerProfileBinding, TriageProfile } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

/**
 * ServerProfileBindingComponent manages triage profile bindings for servers
 * within a project settings page. It provides a table of current bindings,
 * a form to add/edit bindings, and a bulk apply button.
 */
@Component({
  selector: 'app-server-profile-binding',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="bg-white dark:bg-slate-800 rounded-lg shadow">
      <!-- Header -->
      <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@profileBinding.title">Server Profile Bindings</h2>
        <button
          (click)="showForm.set(!showForm())"
          class="text-xs px-3 py-1.5 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          i18n="@@profileBinding.addBinding">
          {{ showForm() ? 'Cancel' : 'Add Binding' }}
        </button>
      </div>

      <!-- Add/Edit Form -->
      @if (showForm()) {
        <div class="px-4 py-3 bg-slate-50 dark:bg-slate-700/30 border-b border-slate-200 dark:border-slate-700">
          <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div>
              <label class="block text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@profileBinding.serverLabel">Server Label</label>
              <input
                type="text"
                class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                [ngModel]="formServerLabel()"
                (ngModelChange)="formServerLabel.set($event)"
                placeholder="e.g., web-prod-01" />
            </div>
            <div>
              <label class="block text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@profileBinding.environment">Environment</label>
              <select
                class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                [ngModel]="formEnvironment()"
                (ngModelChange)="formEnvironment.set($event)">
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="internal">Internal</option>
              </select>
            </div>
            <div>
              <label class="block text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@profileBinding.profile">Profile</label>
              <select
                class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-2 py-1.5 text-slate-900 dark:text-white"
                [ngModel]="formProfile()"
                (ngModelChange)="formProfile.set($event)">
                @for (p of profiles(); track p.name) {
                  <option [value]="p.name">{{ p.name }}</option>
                }
              </select>
            </div>
            <div class="flex items-end">
              <button
                (click)="saveBinding()"
                [disabled]="!formServerLabel()"
                class="w-full px-3 py-1.5 rounded-md text-sm font-medium bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                i18n="@@profileBinding.save">Save</button>
            </div>
          </div>
        </div>
      }

      <!-- Bulk Apply -->
      <div class="px-4 py-2 border-b border-slate-200 dark:border-slate-700 flex items-center gap-3">
        <select
          class="rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-xs px-2 py-1 text-slate-900 dark:text-white"
          [ngModel]="bulkProfile()"
          (ngModelChange)="bulkProfile.set($event)">
          @for (p of profiles(); track p.name) {
            <option [value]="p.name">{{ p.name }}</option>
          }
        </select>
        <select
          class="rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-xs px-2 py-1 text-slate-900 dark:text-white"
          [ngModel]="bulkEnvironment()"
          (ngModelChange)="bulkEnvironment.set($event)">
          <option value="" i18n="@@profileBinding.allEnvs">All Environments</option>
          <option value="production">Production</option>
          <option value="staging">Staging</option>
          <option value="development">Development</option>
          <option value="internal">Internal</option>
        </select>
        <button
          (click)="bulkApply()"
          class="text-xs px-3 py-1 rounded-md bg-amber-600 text-white hover:bg-amber-700 transition-colors"
          i18n="@@profileBinding.bulkApply">Bulk Apply</button>
        @if (statusMessage()) {
          <span class="text-xs text-green-600 dark:text-green-400">{{ statusMessage() }}</span>
        }
      </div>

      <!-- Bindings Table -->
      <div class="overflow-x-auto">
        <table class="w-full text-sm text-left">
          <thead>
            <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
              <th class="px-4 py-2 font-medium" i18n="@@profileBinding.colServer">Server</th>
              <th class="px-4 py-2 font-medium" i18n="@@profileBinding.colEnv">Environment</th>
              <th class="px-4 py-2 font-medium" i18n="@@profileBinding.colProfile">Profile</th>
              <th class="px-4 py-2 font-medium" i18n="@@profileBinding.colDesc">Description</th>
              <th class="px-4 py-2 font-medium" i18n="@@profileBinding.colActions">Actions</th>
            </tr>
          </thead>
          <tbody>
            @for (binding of bindings(); track binding.id) {
              <tr class="border-b border-slate-100 dark:border-slate-700/50">
                <td class="px-4 py-2 font-mono text-xs text-slate-900 dark:text-white">{{ binding.server_label }}</td>
                <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">
                  <span [class]="envBadgeClass(binding.environment)">{{ binding.environment }}</span>
                </td>
                <td class="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-200">{{ binding.profile_name }}</td>
                <td class="px-4 py-2 text-xs text-slate-500 dark:text-slate-400 max-w-xs truncate">{{ binding.description || '-' }}</td>
                <td class="px-4 py-2">
                  <button
                    (click)="deleteBinding(binding.server_label)"
                    class="text-xs text-red-600 dark:text-red-400 hover:underline"
                    i18n="@@profileBinding.remove">Remove</button>
                </td>
              </tr>
            } @empty {
              <tr>
                <td colspan="5" class="px-4 py-6 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@profileBinding.noBindings">
                  No profile bindings configured. Add a binding to assign triage profiles to servers.
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    </div>
  `,
})
export class ServerProfileBindingComponent implements OnInit {
  private readonly triageService = inject(TriageService);

  /** The project ID to manage bindings for */
  readonly projectId = input.required<string>();

  readonly bindings = signal<ServerProfileBinding[]>([]);
  readonly profiles = signal<TriageProfile[]>([]);
  readonly showForm = signal(false);
  readonly statusMessage = signal<string>('');

  // Form fields
  readonly formServerLabel = signal('');
  readonly formEnvironment = signal('production');
  readonly formProfile = signal('default');

  // Bulk apply fields
  readonly bulkProfile = signal('default');
  readonly bulkEnvironment = signal('');

  ngOnInit(): void {
    this.loadBindings();
    this.loadProfiles();
  }

  private loadBindings(): void {
    this.triageService.listBindings(this.projectId()).subscribe({
      next: (b) => this.bindings.set(b),
      error: () => {},
    });
  }

  private loadProfiles(): void {
    this.triageService.listProfiles().subscribe({
      next: (p) => {
        this.profiles.set(p);
        if (p.length > 0) {
          this.formProfile.set(p[0].name);
          this.bulkProfile.set(p[0].name);
        }
      },
      error: () => {},
    });
  }

  saveBinding(): void {
    const serverLabel = this.formServerLabel();
    if (!serverLabel) return;

    this.triageService
      .setBinding(this.projectId(), serverLabel, {
        profile_name: this.formProfile(),
      })
      .subscribe({
        next: () => {
          this.showForm.set(false);
          this.formServerLabel.set('');
          this.statusMessage.set('Binding saved!');
          this.loadBindings();
          setTimeout(() => this.statusMessage.set(''), 3000);
        },
        error: () => {
          this.statusMessage.set('Error saving binding');
          setTimeout(() => this.statusMessage.set(''), 3000);
        },
      });
  }

  deleteBinding(serverLabel: string): void {
    this.triageService.deleteBinding(this.projectId(), serverLabel).subscribe({
      next: () => {
        this.statusMessage.set('Binding removed');
        this.loadBindings();
        setTimeout(() => this.statusMessage.set(''), 3000);
      },
      error: () => {
        this.statusMessage.set('Error removing binding');
        setTimeout(() => this.statusMessage.set(''), 3000);
      },
    });
  }

  bulkApply(): void {
    const targetBindings = this.bindings().filter(
      (b) => !this.bulkEnvironment() || b.environment === this.bulkEnvironment(),
    );

    if (targetBindings.length === 0) {
      this.statusMessage.set('No matching servers found');
      setTimeout(() => this.statusMessage.set(''), 3000);
      return;
    }

    let completed = 0;
    for (const binding of targetBindings) {
      this.triageService
        .setBinding(this.projectId(), binding.server_label, {
          profile_name: this.bulkProfile(),
        })
        .subscribe({
          next: () => {
            completed++;
            if (completed === targetBindings.length) {
              this.statusMessage.set(`Applied "${this.bulkProfile()}" to ${completed} server(s)`);
              this.loadBindings();
              setTimeout(() => this.statusMessage.set(''), 3000);
            }
          },
          error: () => {
            completed++;
          },
        });
    }
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
      default:
        return `${base} bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300`;
    }
  }
}
