import { DatePipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { type APIKey, ApiKeyService } from '../../services/api-key.service';

@Component({
  selector: 'app-api-keys',
  standalone: true,
  imports: [FormsModule, DatePipe],
  template: `
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-3">
          <h1 class="text-2xl font-bold text-slate-900 dark:text-white" i18n="@@apiKeys.title">
            API Keys
          </h1>
          <a
            href="/swagger"
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded-full hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
            i18n="@@apiKeys.docsLink"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
            API Docs
          </a>
        </div>
        <button
          (click)="showCreateForm.set(true)"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@apiKeys.createButton"
        >
          Create API Key
        </button>
      </div>

      <!-- Created key dialog -->
      @if (createdKey()) {
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div class="bg-white dark:bg-slate-800 rounded-lg p-6 max-w-lg w-full mx-4 shadow-xl">
            <div class="flex items-center gap-2 mb-4">
              <svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h3 class="text-lg font-semibold text-slate-900 dark:text-white" i18n="@@apiKeys.createdDialogTitle">
                API Key Created
              </h3>
            </div>
            <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" i18n="@@apiKeys.createdMessage">
              API key created successfully. Copy it now - it will not be shown again.
            </p>
            <div class="flex items-center gap-2 mb-4">
              <code class="flex-1 px-3 py-2 bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded text-sm font-mono text-slate-900 dark:text-white break-all select-all">
                {{ createdKey() }}
              </code>
              <button
                (click)="copyKey()"
                class="px-3 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded transition-colors cursor-pointer whitespace-nowrap"
                i18n="@@apiKeys.copyButton"
              >
                Copy
              </button>
            </div>
            @if (copied()) {
              <p class="text-xs text-green-700 dark:text-green-300 mb-4" i18n="@@apiKeys.copied">Copied!</p>
            }
            <div class="flex justify-end">
              <button
                (click)="closeCreatedKeyDialog()"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@apiKeys.closeDialogButton"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      }

      <!-- Create form -->
      @if (showCreateForm()) {
        <div class="mb-6 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4" i18n="@@apiKeys.createTitle">
            Create New API Key
          </h2>
          <form (ngSubmit)="onCreate()" class="space-y-4">
            <div>
              <label for="keyName" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@apiKeys.nameLabel">
                Name
              </label>
              <input
                id="keyName"
                type="text"
                [(ngModel)]="newKeyName"
                name="keyName"
                required
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="e.g. CI Pipeline"
                i18n-placeholder="@@apiKeys.namePlaceholder"
              />
            </div>
            <div>
              <label for="keyExpiry" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@apiKeys.expiryLabel">
                Expiration
              </label>
              <select
                id="keyExpiry"
                [(ngModel)]="newKeyExpiry"
                name="keyExpiry"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="" i18n="@@apiKeys.expiryNever">Never</option>
                <option value="30" i18n="@@apiKeys.expiry30">30 days</option>
                <option value="90" i18n="@@apiKeys.expiry90">90 days</option>
                <option value="365" i18n="@@apiKeys.expiry365">1 year</option>
              </select>
            </div>
            <div class="flex gap-2">
              <button
                type="submit"
                [disabled]="creating()"
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
                i18n="@@apiKeys.createSubmit"
              >
                Create
              </button>
              <button
                type="button"
                (click)="showCreateForm.set(false)"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@apiKeys.cancelButton"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      }

      <!-- Keys table -->
      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@apiKeys.loading">Loading...</p>
      } @else if (keys().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@apiKeys.noKeys">
          No API keys found. Create one to get started.
        </p>
      } @else {
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@apiKeys.col.name">Name</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@apiKeys.col.prefix">Prefix</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@apiKeys.col.created">Created</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@apiKeys.col.expires">Expires</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@apiKeys.col.actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (key of keys(); track key.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3 text-slate-900 dark:text-white">{{ key.name || '-' }}</td>
                  <td class="px-4 py-3 font-mono text-slate-600 dark:text-slate-400">{{ key.key_prefix }}...</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ key.created_at | date:'short' }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">
                    @if (key.expires_at) {
                      {{ key.expires_at | date:'short' }}
                    } @else {
                      <span i18n="@@apiKeys.never">Never</span>
                    }
                  </td>
                  <td class="px-4 py-3">
                    <button
                      (click)="onDelete(key)"
                      class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 font-medium cursor-pointer"
                      i18n="@@apiKeys.deleteButton"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      <!-- Delete confirmation dialog -->
      @if (confirmDelete()) {
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div class="bg-white dark:bg-slate-800 rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <h3 class="text-lg font-semibold text-slate-900 dark:text-white mb-2" i18n="@@apiKeys.deleteConfirmTitle">
              Delete API Key
            </h3>
            <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" i18n="@@apiKeys.deleteConfirmMessage">
              Are you sure you want to delete this API key? Any integrations using this key will stop working immediately.
            </p>
            <div class="flex gap-2 justify-end">
              <button
                (click)="confirmDelete.set(null)"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@apiKeys.cancelDeleteButton"
              >
                Cancel
              </button>
              <button
                (click)="onConfirmDelete()"
                class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@apiKeys.confirmDeleteButton"
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
export class ApiKeysComponent implements OnInit {
  private readonly apiKeyService = inject(ApiKeyService);

  readonly keys = signal<APIKey[]>([]);
  readonly loading = signal(true);
  readonly creating = signal(false);
  readonly showCreateForm = signal(false);
  readonly createdKey = signal<string>('');
  readonly copied = signal(false);
  readonly confirmDelete = signal<APIKey | null>(null);

  newKeyName = '';
  newKeyExpiry = '';

  ngOnInit(): void {
    this.loadKeys();
  }

  private loadKeys(): void {
    this.loading.set(true);
    this.apiKeyService.list().subscribe({
      next: (keys) => {
        this.keys.set(keys);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  onCreate(): void {
    if (!this.newKeyName) return;

    this.creating.set(true);
    const expiresInDays = this.newKeyExpiry ? parseInt(this.newKeyExpiry, 10) : undefined;

    this.apiKeyService.create(this.newKeyName, expiresInDays).subscribe({
      next: (response) => {
        this.createdKey.set(response.key);
        this.showCreateForm.set(false);
        this.creating.set(false);
        this.newKeyName = '';
        this.newKeyExpiry = '';
        this.copied.set(false);
        this.loadKeys();
      },
      error: () => {
        this.creating.set(false);
      },
    });
  }

  onDelete(key: APIKey): void {
    this.confirmDelete.set(key);
  }

  onConfirmDelete(): void {
    const key = this.confirmDelete();
    if (!key) return;
    this.apiKeyService.delete(key.id).subscribe({
      next: () => {
        this.confirmDelete.set(null);
        this.loadKeys();
      },
    });
  }

  closeCreatedKeyDialog(): void {
    this.createdKey.set('');
    this.copied.set(false);
  }

  copyKey(): void {
    const key = this.createdKey();
    if (key) {
      navigator.clipboard.writeText(key).then(() => {
        this.copied.set(true);
      });
    }
  }
}
