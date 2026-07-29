import { DatePipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { SBOMProject } from '../../models/sbom.model';
import type { Team } from '../../models/team.model';
import { SbomService } from '../../services/sbom.service';
import { TeamService } from '../../services/team.service';

@Component({
  selector: 'app-sbom-projects',
  standalone: true,
  imports: [FormsModule, DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white" i18n="@@sbom.projects.title">
          SBOM Projects
        </h1>
        <button
          (click)="onCreateNew()"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@sbom.projects.createButton"
        >
          Create Project
        </button>
      </div>

      <!-- Create form -->
      @if (showForm()) {
        <div class="mb-6 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4">
            @if (editingProject()) {
              <span i18n="@@sbom.projects.editTitle">Edit Project</span>
            } @else {
              <span i18n="@@sbom.projects.createTitle">Create New Project</span>
            }
          </h2>
          <form #projectForm="ngForm" (ngSubmit)="onSubmitForm()" class="space-y-4">
            <div>
              <label for="projectName" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.projects.nameLabel">
                Project Name
              </label>
              <input
                id="projectName"
                type="text"
                [(ngModel)]="formName"
                name="projectName"
                required
                #nameCtrl="ngModel"
                class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                [class]="nameCtrl.invalid && (nameCtrl.dirty || nameCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                placeholder="e.g. my-application"
                i18n-placeholder="@@sbom.projects.namePlaceholder"
              />
              @if (nameCtrl.invalid && (nameCtrl.dirty || nameCtrl.touched)) {
                <p class="mt-1 text-xs text-red-600 dark:text-red-400" i18n="@@sbom.projects.nameRequired">Project name is required.</p>
              }
            </div>
            <div>
              <label for="projectTeam" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.projects.teamLabel">
                Team (optional)
              </label>
              <select
                id="projectTeam"
                [(ngModel)]="formTeamId"
                name="projectTeam"
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option [ngValue]="null" i18n="@@sbom.projects.noTeam">— No team (personal) —</option>
                @for (t of teams(); track t.id) {
                  <option [ngValue]="t.id">{{ t.name }}</option>
                }
              </select>
            </div>
            <div class="flex gap-2">
              <button
                type="submit"
                [disabled]="submitting() || projectForm.invalid"
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
                i18n="@@sbom.projects.submitButton"
              >
                Create
              </button>
              <button
                type="button"
                (click)="onCancelForm()"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@sbom.projects.cancelButton"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      }

      <!-- Projects list -->
      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.projects.loading">Loading...</p>
      } @else if (projects().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.projects.noProjects">
          No SBOM projects found. Create one to start monitoring.
        </p>
      } @else {
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3" i18n="@@sbom.projects.col.name">Name</th>
                <th class="px-4 py-3" i18n="@@sbom.projects.col.team">Team</th>
                <th class="px-4 py-3" i18n="@@sbom.projects.col.created">Created</th>
                <th class="px-4 py-3" i18n="@@sbom.projects.col.actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (project of projects(); track project.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3">
                    <a
                      [routerLink]="['/sbom', project.id]"
                      class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                    >
                      {{ project.name }}
                    </a>
                  </td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ getTeamName(project.team_id) }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ project.created_at | date:'short' }}</td>
                  <td class="px-4 py-3">
                    <button
                      (click)="onEdit(project)"
                      class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium cursor-pointer mr-3"
                      i18n="@@sbom.projects.editButton"
                    >
                      Edit
                    </button>
                    <button
                      (click)="onDelete(project)"
                      class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 font-medium cursor-pointer"
                      i18n="@@sbom.projects.deleteButton"
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

      <!-- Delete confirmation -->
      @if (confirmDelete()) {
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div class="bg-white dark:bg-slate-800 rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <h3 class="text-lg font-semibold text-slate-900 dark:text-white mb-2" i18n="@@sbom.projects.deleteConfirmTitle">
              Delete Project
            </h3>
            <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" i18n="@@sbom.projects.deleteConfirmMessage">
              Are you sure you want to delete this project? All versions and scan results will be removed.
            </p>
            <div class="flex gap-2 justify-end">
              <button
                (click)="confirmDelete.set(null)"
                class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@sbom.projects.cancelButton"
              >
                Cancel
              </button>
              <button
                (click)="onConfirmDelete()"
                class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-md transition-colors cursor-pointer"
                i18n="@@sbom.projects.confirmDeleteButton"
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
export class SbomProjectsComponent implements OnInit {
  private readonly sbomService = inject(SbomService);
  private readonly teamService = inject(TeamService);

  readonly projects = signal<SBOMProject[]>([]);
  readonly teams = signal<Team[]>([]);
  readonly loading = signal(true);
  readonly submitting = signal(false);
  readonly showForm = signal(false);
  readonly editingProject = signal<SBOMProject | null>(null);
  readonly confirmDelete = signal<SBOMProject | null>(null);

  formName = '';
  formTeamId: number | null = null;

  ngOnInit(): void {
    this.loadProjects();
    this.loadTeams();
  }

  private loadTeams(): void {
    this.teamService.list().subscribe({
      next: (teams) => this.teams.set(teams),
      error: () => {},
    });
  }

  private loadProjects(): void {
    this.loading.set(true);
    this.sbomService.listProjects().subscribe({
      next: (projects) => {
        this.projects.set(projects);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  onCreateNew(): void {
    this.formName = '';
    this.formTeamId = null;
    this.editingProject.set(null);
    this.showForm.set(true);
  }

  onEdit(project: SBOMProject): void {
    this.formName = project.name;
    this.formTeamId = project.team_id ?? null;
    this.editingProject.set(project);
    this.showForm.set(true);
  }

  onCancelForm(): void {
    this.showForm.set(false);
    this.formName = '';
    this.formTeamId = null;
    this.editingProject.set(null);
  }

  onSubmitForm(): void {
    if (!this.formName) return;
    this.submitting.set(true);

    const editing = this.editingProject();
    if (editing) {
      this.sbomService
        .updateProject(editing.id, {
          name: this.formName,
          team_id: this.formTeamId,
        })
        .subscribe({
          next: () => {
            this.showForm.set(false);
            this.submitting.set(false);
            this.formName = '';
            this.formTeamId = null;
            this.editingProject.set(null);
            this.loadProjects();
          },
          error: () => {
            this.submitting.set(false);
          },
        });
    } else {
      this.sbomService.createProject(this.formName, this.formTeamId ?? undefined).subscribe({
        next: () => {
          this.showForm.set(false);
          this.submitting.set(false);
          this.formName = '';
          this.formTeamId = null;
          this.loadProjects();
        },
        error: () => {
          this.submitting.set(false);
        },
      });
    }
  }

  onDelete(project: SBOMProject): void {
    this.confirmDelete.set(project);
  }

  onConfirmDelete(): void {
    const project = this.confirmDelete();
    if (!project) return;
    this.sbomService.deleteProject(project.id).subscribe({
      next: () => {
        this.confirmDelete.set(null);
        this.loadProjects();
      },
    });
  }

  getTeamName(teamId?: number): string {
    if (!teamId) return '—';
    const t = this.teams().find((team) => team.id === teamId);
    return t ? t.name : '—';
  }
}
