import { DatePipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { Team } from '../../models/team.model';
import { TeamService } from '../../services/team.service';

@Component({
  selector: 'app-teams',
  standalone: true,
  imports: [FormsModule, DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white" i18n="@@teams.title">
          Teams
        </h1>
        <button
          (click)="showCreateForm.set(true)"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@teams.createButton"
        >
          Create Team
        </button>
      </div>

      <!-- Create form -->
      @if (showCreateForm()) {
        <div class="mb-6 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4" i18n="@@teams.createTitle">
            Create New Team
          </h2>
          <form (ngSubmit)="onCreateTeam()" class="space-y-4">
            <div>
              <label for="teamName" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@teams.nameLabel">
                Name
              </label>
              <input
                id="teamName"
                type="text"
                [(ngModel)]="formName"
                name="teamName"
                required
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="e.g. platform-team"
                i18n-placeholder="@@teams.namePlaceholder"
              />
            </div>
            <div>
              <label for="teamDesc" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@teams.descriptionLabel">
                Description
              </label>
              <input
                id="teamDesc"
                type="text"
                [(ngModel)]="formDescription"
                name="teamDesc"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Optional description"
                i18n-placeholder="@@teams.descriptionPlaceholder"
              />
            </div>
            <div class="flex gap-2">
              <button
                type="submit"
                [disabled]="!formName()"
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@teams.saveButton"
              >
                Save
              </button>
              <button
                type="button"
                (click)="onCancelCreate()"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@teams.cancelButton"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      }

      <!-- Teams list -->
      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@teams.loading">Loading teams...</p>
      } @else if (teams().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@teams.empty">No teams found. Create one to get started.</p>
      } @else {
        <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          @for (team of teams(); track team.id) {
            <a
              [routerLink]="['/teams', team.id]"
              class="block p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg hover:border-blue-400 dark:hover:border-blue-500 transition-colors"
            >
              <h3 class="text-lg font-semibold text-slate-900 dark:text-white">{{ team.name }}</h3>
              @if (team.description) {
                <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">{{ team.description }}</p>
              }
              <p class="mt-2 text-xs text-slate-400 dark:text-slate-500">
                <span i18n="@@teams.createdAt">Created</span>: {{ team.created_at | date:'mediumDate' }}
              </p>
            </a>
          }
        </div>
      }

      <!-- Error message -->
      @if (error()) {
        <p class="mt-4 text-sm text-red-600 dark:text-red-400">{{ error() }}</p>
      }
    </div>
  `,
})
export class TeamsComponent implements OnInit {
  private readonly teamService = inject(TeamService);

  teams = signal<Team[]>([]);
  loading = signal(true);
  error = signal('');
  showCreateForm = signal(false);
  formName = signal('');
  formDescription = signal('');

  ngOnInit(): void {
    this.loadTeams();
  }

  loadTeams(): void {
    this.loading.set(true);
    this.teamService.list().subscribe({
      next: (teams) => {
        this.teams.set(teams);
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to load teams');
        this.loading.set(false);
      },
    });
  }

  onCreateTeam(): void {
    const name = this.formName().trim();
    if (!name) return;

    this.teamService.create({ name, description: this.formDescription().trim() || undefined }).subscribe({
      next: () => {
        this.showCreateForm.set(false);
        this.formName.set('');
        this.formDescription.set('');
        this.loadTeams();
      },
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to create team');
      },
    });
  }

  onCancelCreate(): void {
    this.showCreateForm.set(false);
    this.formName.set('');
    this.formDescription.set('');
  }
}
