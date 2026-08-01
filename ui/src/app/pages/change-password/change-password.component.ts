import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { AuthService } from '../../services/auth.service';
import { ToastService } from '../../shared/toast/toast.service';

@Component({
  selector: 'app-change-password',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="p-6">
      <div class="max-w-md">
        <form (ngSubmit)="onSubmit()" class="space-y-4">
          <div>
            <label for="currentPassword" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@changePassword.currentPasswordLabel">
              Current Password
            </label>
            <input
              id="currentPassword"
              type="password"
              [(ngModel)]="currentPassword"
              name="currentPassword"
              required
              class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div>
            <label for="newPassword" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@changePassword.newPasswordLabel">
              New Password
            </label>
            <input
              id="newPassword"
              type="password"
              [(ngModel)]="newPassword"
              name="newPassword"
              required
              minlength="8"
              class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p class="mt-1 text-xs text-slate-500 dark:text-slate-400" i18n="@@changePassword.passwordHint">
              Minimum 8 characters
            </p>
          </div>

          <div>
            <label for="confirmPassword" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@changePassword.confirmPasswordLabel">
              Confirm New Password
            </label>
            <input
              id="confirmPassword"
              type="password"
              [(ngModel)]="confirmPassword"
              name="confirmPassword"
              required
              class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          @if (errorMessage()) {
            <div class="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
              <p class="text-sm text-red-700 dark:text-red-300">{{ errorMessage() }}</p>
            </div>
          }

          <div class="flex gap-3 pt-2">
            <button
              type="submit"
              [disabled]="submitting()"
              class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-md transition-colors cursor-pointer"
              i18n="@@changePassword.submitButton"
            >
              Change Password
            </button>
          </div>
        </form>
      </div>
    </div>
  `,
})
export class ChangePasswordComponent {
  private readonly auth = inject(AuthService);
  private readonly toast = inject(ToastService);

  currentPassword = '';
  newPassword = '';
  confirmPassword = '';
  readonly submitting = signal(false);
  readonly errorMessage = signal('');

  onSubmit(): void {
    this.errorMessage.set('');

    if (!this.currentPassword || !this.newPassword || !this.confirmPassword) {
      this.errorMessage.set($localize`:@@changePassword.error.allFieldsRequired:All fields are required`);
      return;
    }

    if (this.newPassword.length < 8) {
      this.errorMessage.set($localize`:@@changePassword.error.tooShort:New password must be at least 8 characters`);
      return;
    }

    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage.set($localize`:@@changePassword.error.mismatch:New passwords do not match`);
      return;
    }

    this.submitting.set(true);

    this.auth.changePassword(this.currentPassword, this.newPassword).subscribe({
      next: () => {
        this.submitting.set(false);
        this.currentPassword = '';
        this.newPassword = '';
        this.confirmPassword = '';
        this.toast.show('success', $localize`:@@changePassword.success:Password changed successfully`);
      },
      error: (err) => {
        this.submitting.set(false);
        const message = err?.error?.error || $localize`:@@changePassword.error.failed:Failed to change password`;
        this.errorMessage.set(message);
      },
    });
  }
}
