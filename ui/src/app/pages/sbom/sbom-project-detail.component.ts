import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';

import { SbomService } from '../../services/sbom.service';
import { SBOMProject, SBOMVersion, SBOMScanResult } from '../../models/sbom.model';

@Component({
  selector: 'app-sbom-project-detail',
  standalone: true,
  imports: [FormsModule, DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <!-- Header -->
      <div class="flex items-center gap-4 mb-6">
        <a routerLink="/sbom" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300" i18n="@@sbom.detail.backToProjects">
          &larr; Back to Projects
        </a>
      </div>

      @if (project()) {
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white mb-6">{{ project()!.name }}</h1>
      }

      <!-- Upload SBOM form -->
      <div class="mb-8">
        <button
          (click)="showUploadForm.set(!showUploadForm())"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@sbom.detail.uploadButton"
        >
          Upload SBOM
        </button>

        @if (showUploadForm()) {
          <div class="mt-4 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
            <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.detail.uploadTitle">
              Upload SBOM File
            </h2>
            <form #uploadForm="ngForm" (ngSubmit)="onUpload()" class="space-y-4">
              <div>
                <label for="sbomVersion" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.detail.versionLabel">
                  Version
                </label>
                <input
                  id="sbomVersion"
                  type="text"
                  [(ngModel)]="uploadVersion"
                  name="sbomVersion"
                  required
                  #versionCtrl="ngModel"
                  class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  [class]="versionCtrl.invalid && (versionCtrl.dirty || versionCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                  placeholder="e.g. 1.0.0"
                  i18n-placeholder="@@sbom.detail.versionPlaceholder"
                />
              </div>
              <div>
                <label for="sbomEnv" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.detail.environmentLabel">
                  Environment
                </label>
                <input
                  id="sbomEnv"
                  type="text"
                  [(ngModel)]="uploadEnvironment"
                  name="sbomEnv"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. production"
                  i18n-placeholder="@@sbom.detail.environmentPlaceholder"
                />
              </div>
              <div>
                <label for="sbomFile" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.detail.fileLabel">
                  SBOM File (JSON)
                </label>
                <input
                  id="sbomFile"
                  type="file"
                  (change)="onFileSelected($event)"
                  accept=".json"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div class="flex gap-2">
                <button
                  type="submit"
                  [disabled]="uploading() || uploadForm.invalid || !selectedFile()"
                  class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
                  i18n="@@sbom.detail.uploadSubmitButton"
                >
                  Upload
                </button>
                <button
                  type="button"
                  (click)="showUploadForm.set(false)"
                  class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                  i18n="@@sbom.detail.cancelButton"
                >
                  Cancel
                </button>
              </div>
            </form>
            @if (uploadError()) {
              <p class="mt-2 text-sm text-red-600 dark:text-red-400">{{ uploadError() }}</p>
            }
          </div>
        }
      </div>

      <!-- Versions list -->
      <h2 class="text-xl font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.detail.versionsTitle">
        Versions
      </h2>

      @if (versionsLoading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.loading">Loading...</p>
      } @else if (versions().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.noVersions">
          No versions uploaded yet. Upload an SBOM to get started.
        </p>
      } @else {
        <div class="overflow-x-auto mb-8">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3" i18n="@@sbom.detail.col.version">Version</th>
                <th class="px-4 py-3" i18n="@@sbom.detail.col.format">Format</th>
                <th class="px-4 py-3" i18n="@@sbom.detail.col.components">Components</th>
                <th class="px-4 py-3" i18n="@@sbom.detail.col.environment">Environment</th>
                <th class="px-4 py-3" i18n="@@sbom.detail.col.created">Created</th>
                <th class="px-4 py-3" i18n="@@sbom.detail.col.actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (ver of versions(); track ver.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ ver.version }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">
                    <span class="px-2 py-0.5 rounded text-xs font-medium bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                      {{ ver.sbom_format || '-' }}
                    </span>
                  </td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ ver.component_count }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ ver.environment || '-' }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ ver.created_at | date:'short' }}</td>
                  <td class="px-4 py-3">
                    <button
                      (click)="onViewScans(ver)"
                      class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium cursor-pointer"
                      i18n="@@sbom.detail.viewScansButton"
                    >
                      Scans
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      <!-- Scan results for selected version -->
      @if (selectedVersion()) {
        <div class="mt-6">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-slate-900 dark:text-white">
              <span i18n="@@sbom.detail.scanResultsFor">Scan Results for</span> {{ selectedVersion()!.version }}
            </h2>
            <button
              (click)="selectedVersion.set(null)"
              class="text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 cursor-pointer"
              i18n="@@sbom.detail.closeScans"
            >
              Close
            </button>
          </div>

          @if (scansLoading()) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.loading">Loading...</p>
          } @else if (scanResults().length === 0) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.noScans">
              No scan results available for this version.
            </p>
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-sm text-left">
                <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                  <tr>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.scannedAt">Scanned At</th>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.status">Status</th>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.findings">Findings</th>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.new">New</th>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.resolved">Resolved</th>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.trigger">Trigger</th>
                    <th class="px-4 py-3" i18n="@@sbom.detail.col.actions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (scan of scanResults(); track scan.id) {
                    <tr class="border-b border-slate-200 dark:border-slate-700">
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ scan.scanned_at | date:'short' }}</td>
                      <td class="px-4 py-3">
                        @if (scan.status === 'completed') {
                          <span class="text-green-600 dark:text-green-400">{{ scan.status }}</span>
                        } @else {
                          <span class="text-red-600 dark:text-red-400">{{ scan.status }}</span>
                        }
                      </td>
                      <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ scan.total_findings }}</td>
                      <td class="px-4 py-3">
                        @if (scan.new_findings > 0) {
                          <span class="text-red-600 dark:text-red-400">+{{ scan.new_findings }}</span>
                        } @else {
                          <span class="text-slate-400">0</span>
                        }
                      </td>
                      <td class="px-4 py-3">
                        @if (scan.resolved_findings > 0) {
                          <span class="text-green-600 dark:text-green-400">-{{ scan.resolved_findings }}</span>
                        } @else {
                          <span class="text-slate-400">0</span>
                        }
                      </td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ scan.trigger }}</td>
                      <td class="px-4 py-3">
                        <a
                          [routerLink]="['/sbom', projectId, 'scans', scan.id]"
                          class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                          i18n="@@sbom.detail.viewDetailButton"
                        >
                          Details
                        </a>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </div>
      }
    </div>
  `,
})
export class SbomProjectDetailComponent implements OnInit {
  private readonly sbomService = inject(SbomService);
  private readonly route = inject(ActivatedRoute);

  readonly project = signal<SBOMProject | null>(null);
  readonly versions = signal<SBOMVersion[]>([]);
  readonly versionsLoading = signal(true);
  readonly scanResults = signal<SBOMScanResult[]>([]);
  readonly scansLoading = signal(false);
  readonly selectedVersion = signal<SBOMVersion | null>(null);

  // Upload form
  readonly showUploadForm = signal(false);
  readonly uploading = signal(false);
  readonly uploadError = signal<string | null>(null);
  readonly selectedFile = signal<File | null>(null);
  uploadVersion = '';
  uploadEnvironment = '';

  projectId = 0;

  ngOnInit(): void {
    this.projectId = Number(this.route.snapshot.paramMap.get('id'));
    this.loadProject();
    this.loadVersions();
  }

  private loadProject(): void {
    this.sbomService.getProject(this.projectId).subscribe({
      next: (project) => this.project.set(project),
    });
  }

  private loadVersions(): void {
    this.versionsLoading.set(true);
    this.sbomService.listVersions(this.projectId).subscribe({
      next: (versions) => {
        this.versions.set(versions);
        this.versionsLoading.set(false);
      },
      error: () => {
        this.versionsLoading.set(false);
      },
    });
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile.set(input.files[0]);
    } else {
      this.selectedFile.set(null);
    }
  }

  onUpload(): void {
    const file = this.selectedFile();
    if (!file || !this.uploadVersion) return;

    this.uploading.set(true);
    this.uploadError.set(null);

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const sbomContent = JSON.parse(reader.result as string);
        this.sbomService.uploadSBOM(this.projectId, this.uploadVersion, this.uploadEnvironment, sbomContent).subscribe({
          next: () => {
            this.uploading.set(false);
            this.showUploadForm.set(false);
            this.uploadVersion = '';
            this.uploadEnvironment = '';
            this.selectedFile.set(null);
            this.loadVersions();
          },
          error: (err) => {
            this.uploading.set(false);
            this.uploadError.set(err?.error?.error || 'Upload failed');
          },
        });
      } catch {
        this.uploading.set(false);
        this.uploadError.set('Invalid JSON file');
      }
    };
    reader.readAsText(file);
  }

  onViewScans(version: SBOMVersion): void {
    this.selectedVersion.set(version);
    this.scansLoading.set(true);
    this.sbomService.listScanResults(version.id).subscribe({
      next: (results) => {
        this.scanResults.set(results);
        this.scansLoading.set(false);
      },
      error: () => {
        this.scansLoading.set(false);
      },
    });
  }
}
