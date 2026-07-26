import { Component, inject } from '@angular/core';

import { ToastService, ToastMessage } from './toast.service';

@Component({
  selector: 'app-toast',
  standalone: true,
  template: `
    <!-- PC: top-right, SP: bottom-center -->
    <div
      class="fixed z-50 flex flex-col gap-2 pointer-events-none
             bottom-4 left-4 right-4 items-center
             md:bottom-auto md:top-4 md:right-4 md:left-auto md:items-end md:w-96"
      aria-live="polite"
      aria-atomic="true"
    >
      @for (toast of toastService.messages(); track toast.id) {
        <div
          class="pointer-events-auto w-full max-w-sm rounded-lg shadow-lg border px-4 py-3 flex items-start gap-3 animate-slide-in"
          [class]="toastClasses(toast)"
          role="alert"
        >
          <!-- Icon -->
          <span class="shrink-0 mt-0.5" [innerHTML]="toastIcon(toast)"></span>

          <!-- Message -->
          <p class="flex-1 text-sm break-words">{{ toast.message }}</p>

          <!-- Close button -->
          <button
            (click)="toastService.dismiss(toast.id)"
            class="shrink-0 p-1 rounded hover:bg-black/10 dark:hover:bg-white/10 transition-colors"
            aria-label="Close"
            i18n-aria-label="@@toast.close"
          >
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      }
    </div>
  `,
  styles: `
    @keyframes slide-in {
      from {
        opacity: 0;
        transform: translateY(-0.5rem);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    @media (max-width: 767px) {
      @keyframes slide-in {
        from {
          opacity: 0;
          transform: translateY(0.5rem);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }
    }
    .animate-slide-in {
      animation: slide-in 0.2s ease-out;
    }
  `,
})
export class ToastComponent {
  readonly toastService = inject(ToastService);

  toastClasses(toast: ToastMessage): string {
    switch (toast.type) {
      case 'error':
        return 'bg-red-50 dark:bg-red-900/80 border-red-300 dark:border-red-700 text-red-800 dark:text-red-200';
      case 'warning':
        return 'bg-amber-50 dark:bg-amber-900/80 border-amber-300 dark:border-amber-700 text-amber-800 dark:text-amber-200';
      case 'info':
        return 'bg-blue-50 dark:bg-blue-900/80 border-blue-300 dark:border-blue-700 text-blue-800 dark:text-blue-200';
      case 'success':
        return 'bg-green-50 dark:bg-green-900/80 border-green-300 dark:border-green-700 text-green-800 dark:text-green-200';
      default:
        return '';
    }
  }

  toastIcon(toast: ToastMessage): string {
    switch (toast.type) {
      case 'error':
        return '<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" /></svg>';
      case 'warning':
        return '<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" /></svg>';
      case 'info':
        return '<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" /></svg>';
      case 'success':
        return '<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>';
      default:
        return '';
    }
  }
}
