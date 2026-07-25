import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap, catchError, of } from 'rxjs';

export interface User {
  id: number;
  email: string;
  name: string;
  role: string;
}

export interface AuthConfig {
  mode: string;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private readonly http = inject(HttpClient);

  readonly isAuthenticated = signal(false);
  readonly currentUser = signal<User | null>(null);
  readonly authMode = signal<string>('none');

  private configLoaded = false;

  /**
   * Fetch the auth configuration from the server.
   */
  getConfig(): Observable<AuthConfig> {
    return this.http.get<AuthConfig>('/auth/config').pipe(
      tap((config) => {
        this.authMode.set(config.mode);
        this.configLoaded = true;
      }),
    );
  }

  /**
   * Log in with email and password (local auth mode).
   */
  login(email: string, password: string): Observable<{ user: User }> {
    return this.http
      .post<{ user: User }>('/auth/login', { email, password }, { withCredentials: true })
      .pipe(
        tap((response) => {
          this.isAuthenticated.set(true);
          this.currentUser.set(response.user);
        }),
      );
  }

  /**
   * Log out the current user.
   */
  logout(): Observable<void> {
    return this.http.post<void>('/auth/logout', {}, { withCredentials: true }).pipe(
      tap(() => {
        this.isAuthenticated.set(false);
        this.currentUser.set(null);
      }),
    );
  }

  /**
   * Check the current session by calling /auth/me.
   */
  getMe(): Observable<User | null> {
    return this.http.get<User>('/auth/me', { withCredentials: true }).pipe(
      tap((user) => {
        this.isAuthenticated.set(true);
        this.currentUser.set(user);
      }),
      catchError(() => {
        this.isAuthenticated.set(false);
        this.currentUser.set(null);
        return of(null);
      }),
    );
  }

  /**
   * Initialize auth state by loading config and checking session.
   */
  init(): Observable<User | null> {
    return new Observable<User | null>((subscriber) => {
      this.getConfig().subscribe({
        next: () => {
          this.getMe().subscribe({
            next: (user) => {
              subscriber.next(user);
              subscriber.complete();
            },
            error: (err) => {
              subscriber.error(err);
            },
          });
        },
        error: (err) => {
          subscriber.error(err);
        },
      });
    });
  }

  /**
   * Returns true if the auth config has been loaded.
   */
  isConfigLoaded(): boolean {
    return this.configLoaded;
  }
}
