import { Injectable, signal } from '@angular/core';

export interface ToastMessage {
  id: number;
  type: 'error' | 'warning' | 'info' | 'success';
  message: string;
  timestamp: number;
}

@Injectable({
  providedIn: 'root',
})
export class ToastService {
  private nextId = 0;
  private readonly _messages = signal<ToastMessage[]>([]);

  readonly messages = this._messages.asReadonly();

  /** Default auto-dismiss duration in ms (0 = no auto-dismiss) */
  private readonly AUTO_DISMISS_MS = 8000;

  show(type: ToastMessage['type'], message: string, autoDismissMs?: number): void {
    const id = this.nextId++;
    const toast: ToastMessage = {
      id,
      type,
      message,
      timestamp: Date.now(),
    };

    this._messages.update((msgs) => [...msgs, toast]);

    const duration = autoDismissMs ?? this.AUTO_DISMISS_MS;
    if (duration > 0) {
      setTimeout(() => this.dismiss(id), duration);
    }
  }

  error(message: string, autoDismissMs?: number): void {
    this.show('error', message, autoDismissMs);
  }

  warning(message: string, autoDismissMs?: number): void {
    this.show('warning', message, autoDismissMs);
  }

  info(message: string, autoDismissMs?: number): void {
    this.show('info', message, autoDismissMs);
  }

  success(message: string, autoDismissMs?: number): void {
    this.show('success', message, autoDismissMs);
  }

  dismiss(id: number): void {
    this._messages.update((msgs) => msgs.filter((m) => m.id !== id));
  }

  clear(): void {
    this._messages.set([]);
  }
}
