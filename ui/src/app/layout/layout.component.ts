import { Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';

import { SidebarComponent } from './sidebar/sidebar.component';
import { HeaderComponent } from './header/header.component';

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
          [pageTitle]="'Vulnerabilities'"
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
  readonly sidebarOpen = signal(false);

  toggleSidebar(): void {
    this.sidebarOpen.update((v) => !v);
  }

  closeSidebar(): void {
    this.sidebarOpen.set(false);
  }
}
