import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 px-4">
      <div class="w-full max-w-md bg-white dark:bg-slate-800 rounded-lg shadow-lg p-8">
        <h1 class="text-2xl font-bold text-center text-slate-900 dark:text-white mb-6" i18n="@@login.title">
          Sign In
        </h1>

        @if (loading()) {
          <div class="text-center text-slate-500 dark:text-slate-400" i18n="@@login.loading">
            Loading...
          </div>
        } @else if (mode() === 'local') {
          <!-- Local auth: email/password form -->
          <form (ngSubmit)="onSubmit()" class="space-y-4">
            <div>
              <label for="email" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@login.emailLabel">
                Email
              </label>
              <input
                id="email"
                type="email"
                [(ngModel)]="email"
                name="email"
                required
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="you@example.com"
                i18n-placeholder="@@login.emailPlaceholder"
              />
            </div>
            <div>
              <label for="password" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@login.passwordLabel">
                Password
              </label>
              <input
                id="password"
                type="password"
                [(ngModel)]="password"
                name="password"
                required
                class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="••••••••"
                i18n-placeholder="@@login.passwordPlaceholder"
              />
            </div>

            @if (error()) {
              <div class="text-sm text-red-600 dark:text-red-400">
                {{ error() }}
              </div>
            }

            <button
              type="submit"
              [disabled]="submitting()"
              class="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
            >
              @if (submitting()) {
                <span i18n="@@login.signingIn">Signing in...</span>
              } @else {
                <span i18n="@@login.signInButton">Sign In</span>
              }
            </button>
          </form>
        } @else if (mode() === 'oidc') {
          <!-- OIDC auth: SSO button -->
          <a
            href="/auth/oidc/login"
            class="block w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md text-center transition-colors"
            i18n="@@login.ssoButton"
          >
            Sign in with SSO
          </a>
        }
      </div>
    </div>
  `,
})
export class LoginComponent implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  email = '';
  password = '';
  readonly mode = signal<string>('');
  readonly loading = signal(true);
  readonly submitting = signal(false);
  readonly error = signal<string>('');

  ngOnInit(): void {
    // Load auth config and check session
    this.authService.getConfig().subscribe({
      next: (config) => {
        this.mode.set(config.mode);

        // If mode is 'none', redirect immediately
        if (config.mode === 'none') {
          this.router.navigate(['/vulnerabilities']);
          return;
        }

        // Check if already authenticated
        this.authService.getMe().subscribe({
          next: (user) => {
            if (user) {
              this.router.navigate(['/vulnerabilities']);
            } else {
              this.loading.set(false);
            }
          },
          error: () => {
            this.loading.set(false);
          },
        });
      },
      error: () => {
        this.loading.set(false);
        this.mode.set('local');
      },
    });
  }

  onSubmit(): void {
    if (!this.email || !this.password) {
      return;
    }

    this.submitting.set(true);
    this.error.set('');

    this.authService.login(this.email, this.password).subscribe({
      next: () => {
        this.router.navigate(['/vulnerabilities']);
      },
      error: () => {
        this.error.set($localize`:@@login.invalidCredentials:Invalid email or password`);
        this.submitting.set(false);
      },
    });
  }
}
