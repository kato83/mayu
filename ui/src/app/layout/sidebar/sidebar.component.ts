import { Component, input, output, inject, computed, signal, OnInit } from '@angular/core';
import { Router, RouterLink, RouterLinkActive } from '@angular/router';
import { catchError, of } from 'rxjs';

import { ThemeService, ThemeMode } from '../../services/theme.service';
import { AuthService } from '../../services/auth.service';
import { VersionService } from '../../services/version.service';

interface NavItem {
  label: string;
  route: string;
  icon: string;
  children?: NavItem[];
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive],
  template: `
    <aside
      [class]="sidebarClasses()"
    >
      <!-- Logo / App name -->
      <div class="flex items-center justify-between h-16 px-6 border-b border-slate-700">
        <span class="text-xl font-bold tracking-wide" i18n="@@sidebar.appName">Mayu</span>
        <!-- Close button (mobile only) -->
        <button
          class="md:hidden text-slate-400 hover:text-white"
          (click)="closed.emit()"
          aria-label="Close menu"
          i18n-aria-label="@@sidebar.closeMenu"
        >
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <!-- Navigation -->
      <nav class="flex-1 overflow-y-auto py-4">
        <ul class="space-y-1 px-3">
          @for (item of navItems(); track item.route) {
            <li>
              @if (item.children) {
                <!-- Parent item with children -->
                <a
                  [routerLink]="item.route"
                  routerLinkActive="bg-slate-700 text-white"
                  [routerLinkActiveOptions]="{ exact: true }"
                  (click)="closed.emit()"
                  class="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
                >
                  <span class="text-lg">{{ item.icon }}</span>
                  <span>{{ item.label }}</span>
                </a>
                <!-- Children -->
                <ul class="mt-1 space-y-1">
                  @for (child of item.children; track child.route) {
                    <li>
                      <a
                        [routerLink]="child.route"
                        routerLinkActive="bg-slate-700 text-white"
                        [routerLinkActiveOptions]="{ exact: true }"
                        (click)="closed.emit()"
                        class="flex items-center gap-3 pl-9 pr-3 py-2 rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
                      >
                        <span class="text-lg">{{ child.icon }}</span>
                        <span>{{ child.label }}</span>
                      </a>
                    </li>
                  }
                </ul>
              } @else {
                <!-- Simple item without children -->
                <a
                  [routerLink]="item.route"
                  routerLinkActive="bg-slate-700 text-white"
                  (click)="closed.emit()"
                  class="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
                >
                  <span class="text-lg">{{ item.icon }}</span>
                  <span>{{ item.label }}</span>
                </a>
              }
            </li>
          }
        </ul>
      </nav>

      <!-- Theme switcher -->
      <div class="px-4 py-4 border-t border-slate-700">
        <p class="text-xs text-slate-400 mb-2" i18n="@@sidebar.theme">Theme</p>
        <div class="flex gap-1">
          <button
            (click)="setTheme('light')"
            [class]="themeButtonClasses('light')"
            title="Light"
            i18n-title="@@sidebar.themeLight"
          >☀️</button>
          <button
            (click)="setTheme('dark')"
            [class]="themeButtonClasses('dark')"
            title="Dark"
            i18n-title="@@sidebar.themeDark"
          >🌙</button>
          <button
            (click)="setTheme('system')"
            [class]="themeButtonClasses('system')"
            title="System"
            i18n-title="@@sidebar.themeSystem"
          >💻</button>
        </div>
      </div>

      <!-- User info & Logout (hidden when auth mode is 'none') -->
      @if (authService.authMode() !== 'none' && authService.currentUser()) {
        <div class="px-4 py-3 border-t border-slate-700">
          <p class="text-xs text-slate-400 truncate">{{ authService.currentUser()!.email }}</p>
          <button
            (click)="onLogout()"
            class="mt-2 w-full text-left text-sm text-slate-300 hover:text-white transition-colors cursor-pointer"
            i18n="@@sidebar.logout"
          >
            Logout
          </button>
        </div>
      }

      <!-- Footer -->
      <div class="px-6 py-4 border-t border-slate-700 text-xs text-slate-400">
        @if (version()) {
          <span i18n="@@sidebar.version">v{{ version() }}</span>
          <span class="mx-1">·</span>
        }
        © 2026 Mayu Project
      </div>
    </aside>
  `,
})
export class SidebarComponent implements OnInit {
  private readonly themeService = inject(ThemeService);
  private readonly router = inject(Router);
  private readonly versionService = inject(VersionService);
  readonly authService = inject(AuthService);

  /** Application version fetched from the API */
  readonly version = signal('');

  /** Whether the sidebar is open (mobile) */
  open = input(false);

  /** Emitted when sidebar should close */
  closed = output<void>();

  private readonly allNavItems: NavItem[] = [
    { label: $localize`:@@sidebar.nav.vulnerabilities:Vulnerabilities`, route: '/vulnerabilities', icon: '🛡️' },
    {
      label: $localize`:@@sidebar.nav.ingest:Ingest`, route: '/ingest', icon: '📥',
      children: [
        { label: $localize`:@@sidebar.nav.ingestJobs:Ingest Jobs`, route: '/ingest/jobs', icon: '📋' },
      ],
    },
    { label: $localize`:@@sidebar.nav.status:Status`, route: '/status', icon: '📊' },
    { label: $localize`:@@sidebar.nav.webhooks:Webhooks`, route: '/webhooks', icon: '🔔' },
    { label: $localize`:@@sidebar.nav.watchlists:Watchlists`, route: '/watchlists', icon: '👁️' },
    { label: $localize`:@@sidebar.nav.apiKeys:API Keys`, route: '/api-keys', icon: '🔑' },
  ];

  readonly navItems = computed(() => {
    if (this.authService.authMode() === 'none') {
      return this.allNavItems.filter((item) => item.route !== '/api-keys');
    }
    return this.allNavItems;
  });

  ngOnInit(): void {
    this.versionService.getVersion().pipe(
      catchError(() => of({ version: '' })),
    ).subscribe({
      next: (res) => this.version.set(res.version),
    });
  }

  setTheme(mode: ThemeMode): void {
    this.themeService.setMode(mode);
  }

  themeButtonClasses(mode: ThemeMode): string {
    const base = 'flex-1 py-1.5 text-center text-sm rounded cursor-pointer transition-colors';
    if (this.themeService.mode() === mode) {
      return `${base} bg-slate-700 text-white`;
    }
    return `${base} text-slate-400 hover:text-white hover:bg-slate-800`;
  }

  sidebarClasses(): string {
    const base = 'fixed inset-y-0 left-0 z-30 w-64 bg-slate-900 text-slate-100 flex flex-col transition-transform duration-200 ease-in-out';
    if (this.open()) {
      return `${base} translate-x-0`;
    }
    // On desktop (md+), always visible. On mobile, hidden by default.
    return `${base} -translate-x-full md:translate-x-0`;
  }

  onLogout(): void {
    this.authService.logout().subscribe({
      next: () => {
        this.router.navigate(['/login']);
      },
    });
  }
}
