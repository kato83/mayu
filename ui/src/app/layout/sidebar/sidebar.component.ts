import { Component, computed, inject, input, type OnInit, output, signal } from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive } from '@angular/router';
import { filter } from 'rxjs/operators';

import { AuthService } from '../../services/auth.service';
import { type ThemeMode, ThemeService } from '../../services/theme.service';
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
        <a routerLink="/dashboard" (click)="closed.emit()" class="text-xl font-bold tracking-wide hover:text-indigo-300 transition-colors cursor-pointer" i18n="@@sidebar.appName">Mayu</a>
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
                <!-- Parent item with collapsible children -->
                <button
                  type="button"
                  (click)="toggleSubnav(item.route)"
                  class="flex items-center gap-3 px-3 py-2.5 w-full rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer select-none"
                  [class.bg-slate-800]="isExpanded(item.route)"
                  [attr.aria-expanded]="isExpanded(item.route)"
                >
                  <span class="text-lg">{{ item.icon }}</span>
                  <span class="flex-1 text-left">{{ item.label }}</span>
                  <svg
                    class="w-4 h-4 transition-transform duration-200"
                    [class.rotate-90]="isExpanded(item.route)"
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                  >
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                  </svg>
                </button>
                <!-- Children (collapsible) -->
                @if (isExpanded(item.route)) {
                  <ul class="mt-1 space-y-1">
                    <li>
                      <a
                        [routerLink]="item.route"
                        routerLinkActive="bg-slate-700 text-white"
                        [routerLinkActiveOptions]="{ exact: true }"
                        (click)="closed.emit()"
                        class="flex items-center gap-3 pl-6 pr-3 py-2.5 rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
                      >
                        <span class="text-lg">{{ item.icon }}</span>
                        <span>{{ item.label }}</span>
                      </a>
                    </li>
                    @for (child of item.children; track child.route) {
                      <li>
                        <a
                          [routerLink]="child.route"
                          routerLinkActive="bg-slate-700 text-white"
                          [routerLinkActiveOptions]="{ exact: true }"
                          (click)="closed.emit()"
                          class="flex items-center gap-3 pl-6 pr-3 py-2.5 rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
                        >
                          <span class="text-lg">{{ child.icon }}</span>
                          <span>{{ child.label }}</span>
                        </a>
                      </li>
                    }
                  </ul>
                }
              } @else {
                <!-- Simple item without children -->
                <a
                  [routerLink]="item.route"
                  routerLinkActive="bg-slate-700 text-white"
                  (click)="closed.emit()"
                  class="flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
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
          <div class="flex items-center gap-2">
            <p class="text-sm text-slate-200 truncate font-medium">{{ authService.currentUser()!.name }}</p>
            @if (authService.currentUser()!.role === 'admin') {
              <span
                class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-300"
                data-testid="role-badge-admin"
                i18n="@@sidebar.roleAdmin"
              >Admin</span>
            } @else if (authService.currentUser()!.role === 'viewer') {
              <span
                class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-slate-500/20 text-blue-300"
                data-testid="role-badge-viewer"
                i18n="@@sidebar.roleViewer"
              >Viewer</span>
            }
          </div>
          <p class="text-xs text-slate-400 truncate mt-0.5">{{ authService.currentUser()!.email }}</p>
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
          <p i18n="@@sidebar.version">Mayu v{{ version() }}</p>
        }
        <div class="flex items-center justify-between">
          <span>© 2026 Mayu Project</span>
          <a
            href="https://github.com/kato83/mayu"
            target="_blank"
            rel="noopener noreferrer"
            class="text-slate-400 hover:text-white transition-colors"
            title="GitHub"
            i18n-title="@@sidebar.github"
          >
            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2Z" />
            </svg>
          </a>
        </div>
      </div>
    </aside>
  `,
})
export class SidebarComponent implements OnInit {
  private readonly themeService = inject(ThemeService);
  private readonly router = inject(Router);
  private readonly versionService = inject(VersionService);
  readonly authService = inject(AuthService);

  /** Application version loaded from API */
  readonly version = signal<string | null>(null);

  /** Set of expanded parent routes */
  private readonly expandedRoutes = signal<Set<string>>(new Set());

  /** Whether the sidebar is open (mobile) */
  open = input(false);

  /** Emitted when sidebar should close */
  closed = output<void>();

  ngOnInit(): void {
    this.versionService.getVersion().subscribe({
      next: (res) => this.version.set(res.version),
      error: (err) => console.warn('Failed to fetch version:', err),
    });

    // Auto-expand subnav if current route matches a child
    this.expandIfCurrentRouteIsChild(this.router.url);

    // Listen to route changes for auto-expanding
    this.router.events.pipe(filter((e): e is NavigationEnd => e instanceof NavigationEnd)).subscribe((e) => {
      this.expandIfCurrentRouteIsChild(e.urlAfterRedirects);
    });
  }

  private readonly allNavItems: NavItem[] = [
    { label: $localize`:@@sidebar.nav.vulnerabilities:Vulnerabilities`, route: '/vulnerabilities', icon: '🛡️' },
    { label: $localize`:@@sidebar.nav.epssTrending:EPSS Trending`, route: '/epss-trending', icon: '📈' },
    {
      label: $localize`:@@sidebar.nav.ingest:Ingest`,
      route: '/ingest',
      icon: '📥',
      children: [{ label: $localize`:@@sidebar.nav.ingestJobs:Ingest Jobs`, route: '/ingest/jobs', icon: '📋' }],
    },
    { label: $localize`:@@sidebar.nav.status:Status`, route: '/status', icon: '⚙️' },
    { label: $localize`:@@sidebar.nav.sbom:SBOM`, route: '/sbom', icon: '📦' },
    { label: $localize`:@@sidebar.nav.teams:Teams`, route: '/teams', icon: '👥' },
    { label: $localize`:@@sidebar.nav.webhooks:Webhooks`, route: '/webhooks', icon: '🔔' },
    { label: $localize`:@@sidebar.nav.watchlists:Watchlists`, route: '/watchlists', icon: '🏷️' },
    { label: $localize`:@@sidebar.nav.apiKeys:API Keys`, route: '/api-keys', icon: '🔑' },
    { label: $localize`:@@sidebar.nav.changePassword:Change Password`, route: '/change-password', icon: '🔒' },
    { label: $localize`:@@sidebar.nav.docs:Docs`, route: '/docs', icon: '📖' },
  ];

  readonly navItems = computed(() => {
    const mode = this.authService.authMode();
    return this.allNavItems.filter((item) => {
      if (item.route === '/api-keys' && mode === 'none') {
        return false;
      }
      if (item.route === '/change-password' && mode !== 'local') {
        return false;
      }
      return true;
    });
  });

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
    const base =
      'fixed inset-y-0 left-0 z-30 w-64 bg-slate-900 text-slate-100 flex flex-col transition-transform duration-200 ease-in-out';
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

  /** Toggle subnav expansion for a parent route */
  toggleSubnav(route: string): void {
    const current = new Set(this.expandedRoutes());
    if (current.has(route)) {
      current.delete(route);
    } else {
      current.add(route);
    }
    this.expandedRoutes.set(current);
  }

  /** Check if a subnav is expanded */
  isExpanded(route: string): boolean {
    return this.expandedRoutes().has(route);
  }

  /** Auto-expand subnav if current URL matches a parent or its children */
  private expandIfCurrentRouteIsChild(url: string): void {
    const items = this.allNavItems.filter((item) => item.children);
    for (const item of items) {
      const matches =
        url === item.route ||
        url.startsWith(`${item.route}/`) ||
        item.children!.some((child) => url === child.route || url.startsWith(`${child.route}/`));
      if (matches) {
        const current = new Set(this.expandedRoutes());
        current.add(item.route);
        this.expandedRoutes.set(current);
      }
    }
  }
}
