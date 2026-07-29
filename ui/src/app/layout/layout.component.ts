import { Component, inject, signal } from '@angular/core';
import { NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';
import { HeaderComponent } from './header/header.component';
import { SidebarComponent } from './sidebar/sidebar.component';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [RouterOutlet, SidebarComponent, HeaderComponent],
  template: `
    <div class="min-h-screen bg-slate-50 dark:bg-slate-900">
      <!-- Mobile overlay -->
      @if (sidebarOpen()) {
        <div
          class="fixed inset-0 z-20 bg-black/50 md:hidden"
          (click)="closeSidebar()"
        ></div>
      }

      <!-- Sidebar -->
      <app-sidebar
        [open]="sidebarOpen()"
        (closed)="closeSidebar()"
      />

      <!-- Main content area -->
      <div class="md:ml-64 flex flex-col min-h-screen">
        <!-- Header -->
        <app-header
          [pageTitle]="pageTitle()"
          (menuToggle)="toggleSidebar()"
        />

        <!-- Page content -->
        <main class="flex-1 p-4 md:p-6">
          <router-outlet />
        </main>
      </div>
    </div>
  `,
})
export class LayoutComponent {
  private readonly router = inject(Router);
  readonly sidebarOpen = signal(false);
  readonly pageTitle = signal($localize`:@@layout.title.dashboard:Dashboard`);

  private readonly titleMap: Record<string, string> = {
    '/dashboard': $localize`:@@layout.title.dashboard:Dashboard`,
    '/vulnerabilities': $localize`:@@layout.title.vulnerabilities:Vulnerabilities`,
    '/ingest': $localize`:@@layout.title.ingest:Ingest`,
    '/ingest/jobs': $localize`:@@layout.title.ingestJobs:Ingest Jobs`,
    '/status': $localize`:@@layout.title.status:Status`,
    '/webhooks': $localize`:@@layout.title.webhooks:Webhooks`,
    '/watchlists': $localize`:@@layout.title.watchlists:Watchlists`,
    '/api-keys': $localize`:@@layout.title.apiKeys:API Keys`,
    '/docs': $localize`:@@layout.title.docs:Docs`,
  };

  constructor() {
    this.router.events.pipe(filter((e) => e instanceof NavigationEnd)).subscribe((e) => {
      const url = (e as NavigationEnd).urlAfterRedirects || (e as NavigationEnd).url;
      this.updateTitle(url);
    });
  }

  private updateTitle(url: string): void {
    // Try exact match first, then prefix match
    if (this.titleMap[url]) {
      this.pageTitle.set(this.titleMap[url]);
      return;
    }
    // Find longest prefix match
    const match = Object.keys(this.titleMap)
      .filter((key) => url.startsWith(key))
      .sort((a, b) => b.length - a.length)[0];
    if (match) {
      this.pageTitle.set(this.titleMap[match]);
    } else {
      this.pageTitle.set(this.titleMap['/dashboard']);
    }
  }

  toggleSidebar(): void {
    this.sidebarOpen.update((v) => !v);
  }

  closeSidebar(): void {
    this.sidebarOpen.set(false);
  }
}
