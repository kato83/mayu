import { Component, input, output } from '@angular/core';

@Component({
  selector: 'app-header',
  standalone: true,
  template: `
    <header class="sticky top-0 z-20 h-16 bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700 flex items-center px-4 md:px-6 shadow-sm">
      <!-- Hamburger menu button (mobile only) -->
      <button
        class="md:hidden mr-3 p-1.5 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
        (click)="menuToggle.emit()"
        aria-label="Open menu"
        i18n-aria-label="@@header.openMenu"
      >
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      <h1 class="text-lg font-semibold text-slate-800 dark:text-slate-100">{{ pageTitle() }}</h1>
    </header>
  `,
})
export class HeaderComponent {
  pageTitle = input<string>('');
  menuToggle = output<void>();
}
