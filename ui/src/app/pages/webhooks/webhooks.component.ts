import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { Team } from '../../models/team.model';
import { TeamService } from '../../services/team.service';
import { type Webhook, WebhookService } from '../../services/webhook.service';

@Component({
  selector: 'app-webhooks',
  standalone: true,
  imports: [FormsModule, RouterLink],
  template: `
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white" i18n="@@webhooks.title">
          Webhooks
        </h1>
        <button
          (click)="showCreateForm.set(true)"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@webhooks.createButton"
        >
          Create Webhook
        </button>
      </div>

      <!-- Test result alert -->
      @if (testResult()) {
        <div
          class="mb-6 p-4 rounded-lg border"
          [class]="testResult()!.success
            ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'"
        >
          <p
            class="text-sm font-medium"
            [class]="testResult()!.success
              ? 'text-green-800 dark:text-green-200'
              : 'text-red-800 dark:text-red-200'"
          >
            @if (testResult()!.success) {
              <span i18n="@@webhooks.testSuccess">Test webhook sent successfully.</span>
              @if (testResult()!.status_code) {
                (Status: {{ testResult()!.status_code }})
              }
            } @else {
              <span i18n="@@webhooks.testFailed">Test webhook failed.</span>
              @if (testResult()!.error) {
                {{ testResult()!.error }}
              }
            }
          </p>
          <button
            (click)="testResult.set(null)"
            class="mt-2 text-xs underline cursor-pointer"
            [class]="testResult()!.success
              ? 'text-green-700 dark:text-green-300'
              : 'text-red-700 dark:text-red-300'"
            i18n="@@webhooks.dismissAlert"
          >
            Dismiss
          </button>
        </div>
      }

      <!-- Create/Edit form -->
      @if (showCreateForm() || editingWebhook()) {
        <div class="mb-6 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4">
            @if (editingWebhook()) {
              <span i18n="@@webhooks.editTitle">Edit Webhook</span>
            } @else {
              <span i18n="@@webhooks.createTitle">Create New Webhook</span>
            }
          </h2>
          <form #webhookForm="ngForm" (ngSubmit)="onSubmit()" class="space-y-4">
            <div>
              <label for="webhookName" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.nameLabel">
                Name
              </label>
              <input
                id="webhookName"
                type="text"
                [(ngModel)]="formName"
                name="webhookName"
                required
                #nameCtrl="ngModel"
                class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                [class]="nameCtrl.invalid && (nameCtrl.dirty || nameCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                placeholder="e.g. security-team-slack"
                i18n-placeholder="@@webhooks.namePlaceholder"
              />
              @if (nameCtrl.invalid && (nameCtrl.dirty || nameCtrl.touched)) {
                <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@webhooks.nameRequired">Name is required.</p>
              }
            </div>
            <div>
              <label for="webhookUrl" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.urlLabel">
                URL
              </label>
              <input
                id="webhookUrl"
                type="url"
                [(ngModel)]="formUrl"
                name="webhookUrl"
                required
                pattern="https?://.+"
                #urlCtrl="ngModel"
                class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                [class]="urlCtrl.invalid && (urlCtrl.dirty || urlCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                placeholder="https://hooks.slack.com/services/..."
                i18n-placeholder="@@webhooks.urlPlaceholder"
              />
              @if (urlCtrl.invalid && (urlCtrl.dirty || urlCtrl.touched)) {
                @if (urlCtrl.errors?.['required']) {
                  <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@webhooks.urlRequired">URL is required.</p>
                } @else {
                  <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@webhooks.urlInvalid">Please enter a valid URL (http:// or https://).</p>
                }
              }
            </div>
            <div>
              <label for="webhookEvents" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.eventsLabel">
                Events (comma-separated)
              </label>
              <input
                id="webhookEvents"
                type="text"
                [(ngModel)]="formEvents"
                name="webhookEvents"
                required
                #eventsCtrl="ngModel"
                class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                [class]="eventsCtrl.invalid && (eventsCtrl.dirty || eventsCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                placeholder="new_critical, new_high, *"
                i18n-placeholder="@@webhooks.eventsPlaceholder"
              />
              @if (eventsCtrl.invalid && (eventsCtrl.dirty || eventsCtrl.touched)) {
                <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@webhooks.eventsRequired">Events are required.</p>
              }
            </div>
            <div>
              <label for="webhookContentType" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.contentTypeLabel">
                Content Type
              </label>
              <select
                id="webhookContentType"
                [(ngModel)]="formContentType"
                name="webhookContentType"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="application/json">application/json</option>
              </select>
            </div>
            <div>
              <label for="webhookBodyTemplate" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.bodyTemplateLabel">
                Body Template
              </label>
              <textarea
                id="webhookBodyTemplate"
                [(ngModel)]="formBodyTemplate"
                name="webhookBodyTemplate"
                rows="5"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                placeholder='{"text": "..."}'
                i18n-placeholder="@@webhooks.bodyTemplatePlaceholder"
              ></textarea>
            </div>
            <div>
              <label for="webhookSecret" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.secretLabel">
                Secret
              </label>
              <input
                id="webhookSecret"
                type="password"
                [(ngModel)]="formSecret"
                name="webhookSecret"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Optional HMAC secret"
                i18n-placeholder="@@webhooks.secretPlaceholder"
              />
            </div>
            <div class="flex items-center gap-2">
              <input
                id="webhookEnabled"
                type="checkbox"
                [(ngModel)]="formEnabled"
                name="webhookEnabled"
                class="h-4 w-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500"
              />
              <label for="webhookEnabled" class="text-sm font-medium text-slate-700 dark:text-slate-300" i18n="@@webhooks.enabledLabel">
                Enabled
              </label>
            </div>
            <div>
              <label for="webhookTeam" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@webhooks.teamLabel">
                Team (optional)
              </label>
              <select
                id="webhookTeam"
                [(ngModel)]="formTeamId"
                name="webhookTeam"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option [ngValue]="null" i18n="@@webhooks.noTeam">— No team (personal) —</option>
                @for (t of teams(); track t.id) {
                  <option [ngValue]="t.id">{{ t.name }}</option>
                }
              </select>
            </div>
            <div class="flex gap-2">
              <button
                type="submit"
                [disabled]="submitting() || webhookForm.invalid"
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
                i18n="@@webhooks.saveButton"
              >
                Save
              </button>
              <button
                type="button"
                (click)="onCancelForm()"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@webhooks.cancelButton"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      }

      <!-- Webhooks table -->
      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@webhooks.loading">Loading...</p>
      } @else if (webhooks().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@webhooks.noWebhooks">
          No webhooks found. Create one to get started.
        </p>
      } @else {
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.col.name">Name</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.col.url">URL</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.col.events">Events</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.col.enabled">Enabled</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.col.actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (webhook of webhooks(); track webhook.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3 text-slate-900 dark:text-white">{{ webhook.name }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400 font-mono text-xs max-w-xs truncate">{{ webhook.url }}</td>
                  <td class="px-4 py-3">
                    <div class="flex flex-wrap gap-1">
                      @for (event of webhook.events; track event) {
                        <span class="inline-block px-2 py-0.5 text-xs font-medium rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200">
                          {{ event }}
                        </span>
                      }
                    </div>
                  </td>
                  <td class="px-4 py-3">
                    @if (webhook.enabled) {
                      <span class="inline-block px-2 py-0.5 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200" i18n="@@webhooks.statusEnabled">
                        Enabled
                      </span>
                    } @else {
                      <span class="inline-block px-2 py-0.5 text-xs font-medium rounded-full bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400" i18n="@@webhooks.statusDisabled">
                        Disabled
                      </span>
                    }
                  </td>
                  <td class="px-4 py-3">
                    <div class="flex items-center gap-2">
                      <button
                        (click)="onEdit(webhook)"
                        class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium cursor-pointer"
                        i18n="@@webhooks.editButton"
                      >
                        Edit
                      </button>
                      <button
                        (click)="onTest(webhook)"
                        [disabled]="testing()"
                        class="text-amber-600 hover:text-amber-800 dark:text-amber-400 dark:hover:text-amber-300 font-medium cursor-pointer disabled:opacity-50"
                        i18n="@@webhooks.testButton"
                      >
                        Test
                      </button>
                      <a
                        [routerLink]="['/webhooks', webhook.id, 'deliveries']"
                        class="text-slate-600 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-300 font-medium"
                        i18n="@@webhooks.deliveriesLink"
                      >
                        Logs
                      </a>
                      <button
                        (click)="onDelete(webhook)"
                        class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 font-medium cursor-pointer"
                        i18n="@@webhooks.deleteButton"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </div>
  `,
})
export class WebhooksComponent implements OnInit {
  private readonly webhookService = inject(WebhookService);
  private readonly teamService = inject(TeamService);

  readonly webhooks = signal<Webhook[]>([]);
  readonly teams = signal<Team[]>([]);
  readonly loading = signal(true);
  readonly submitting = signal(false);
  readonly testing = signal(false);
  readonly showCreateForm = signal(false);
  readonly editingWebhook = signal<Webhook | null>(null);
  readonly testResult = signal<{ success: boolean; status_code?: number; error?: string } | null>(null);

  formName = '';
  formUrl = '';
  formEvents = '';
  formContentType = 'application/json';
  formBodyTemplate = '';
  formSecret = '';
  formEnabled = true;
  formTeamId: number | null = null;

  ngOnInit(): void {
    this.loadWebhooks();
    this.teamService.list().subscribe({
      next: (teams) => this.teams.set(teams),
      error: () => {},
    });
  }

  private loadWebhooks(): void {
    this.loading.set(true);
    this.webhookService.list().subscribe({
      next: (webhooks) => {
        this.webhooks.set(webhooks);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  onSubmit(): void {
    if (!this.formName || !this.formUrl || !this.formEvents) return;

    this.submitting.set(true);
    const events = this.formEvents
      .split(',')
      .map((e) => e.trim())
      .filter((e) => e.length > 0);
    const payload: Partial<Webhook> = {
      name: this.formName,
      url: this.formUrl,
      events,
      content_type: this.formContentType,
      body_template: this.formBodyTemplate,
      secret: this.formSecret || undefined,
      enabled: this.formEnabled,
      team_id: this.formTeamId ?? undefined,
    };

    const editing = this.editingWebhook();
    if (editing) {
      this.webhookService.update(editing.id, payload).subscribe({
        next: () => {
          this.resetForm();
          this.loadWebhooks();
        },
        error: () => {
          this.submitting.set(false);
        },
      });
    } else {
      this.webhookService.create(payload).subscribe({
        next: () => {
          this.resetForm();
          this.loadWebhooks();
        },
        error: () => {
          this.submitting.set(false);
        },
      });
    }
  }

  onEdit(webhook: Webhook): void {
    this.editingWebhook.set(webhook);
    this.showCreateForm.set(false);
    this.formName = webhook.name;
    this.formUrl = webhook.url;
    this.formEvents = webhook.events.join(', ');
    this.formContentType = webhook.content_type;
    this.formBodyTemplate = webhook.body_template;
    this.formSecret = '';
    this.formEnabled = webhook.enabled;
  }

  onTest(webhook: Webhook): void {
    this.testing.set(true);
    this.testResult.set(null);
    this.webhookService.test(webhook.id).subscribe({
      next: (result) => {
        this.testResult.set(result);
        this.testing.set(false);
      },
      error: () => {
        this.testResult.set({ success: false, error: 'Request failed' });
        this.testing.set(false);
      },
    });
  }

  onDelete(webhook: Webhook): void {
    this.webhookService.delete(webhook.id).subscribe({
      next: () => {
        this.loadWebhooks();
      },
    });
  }

  onCancelForm(): void {
    this.resetForm();
  }

  private resetForm(): void {
    this.showCreateForm.set(false);
    this.editingWebhook.set(null);
    this.submitting.set(false);
    this.formName = '';
    this.formUrl = '';
    this.formEvents = '';
    this.formContentType = 'application/json';
    this.formBodyTemplate = '';
    this.formSecret = '';
    this.formEnabled = true;
  }
}
