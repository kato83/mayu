import { Injectable, signal } from '@angular/core';

export type ThemeMode = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'mayu-theme';

/**
 * Service to manage the application theme (light/dark/system).
 * Persists the user's choice in localStorage and applies the "dark" class to <html>.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  readonly mode = signal<ThemeMode>(this.loadMode());

  private mediaQuery = window.matchMedia?.('(prefers-color-scheme: dark)') ?? { matches: false, addEventListener: () => {} } as unknown as MediaQueryList;

  constructor() {
    this.applyTheme();
    this.mediaQuery.addEventListener?.('change', () => {
      if (this.mode() === 'system') {
        this.applyTheme();
      }
    });
  }

  /** Set the theme mode and persist to localStorage. */
  setMode(mode: ThemeMode): void {
    this.mode.set(mode);
    localStorage.setItem(STORAGE_KEY, mode);
    this.applyTheme();
  }

  private loadMode(): ThemeMode {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      return stored;
    }
    return 'system';
  }

  private applyTheme(): void {
    const isDark = this.mode() === 'dark' ||
      (this.mode() === 'system' && this.mediaQuery.matches);

    document.documentElement.classList.toggle('dark', isDark);
  }
}
