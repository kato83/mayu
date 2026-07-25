import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach } from 'vitest';

import { SidebarComponent } from './sidebar.component';
import { AuthService } from '../../services/auth.service';

describe('SidebarComponent', () => {
  let fixture: ComponentFixture<SidebarComponent>;
  let component: SidebarComponent;
  let authService: AuthService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    authService = TestBed.inject(AuthService);
    fixture = TestBed.createComponent(SidebarComponent);
    component = fixture.componentInstance;
  });

  it('should create the component', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  describe('role badge', () => {
    it('should display admin role badge when user has admin role', () => {
      authService.authMode.set('local');
      authService.currentUser.set({
        id: 1,
        email: 'admin@example.com',
        name: 'Admin User',
        role: 'admin',
      });
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const badge = el.querySelector('[data-testid="role-badge-admin"]');
      expect(badge).toBeTruthy();
      expect(badge!.textContent).toContain('Admin');
    });

    it('should display viewer role badge when user has viewer role', () => {
      authService.authMode.set('local');
      authService.currentUser.set({
        id: 2,
        email: 'viewer@example.com',
        name: 'Viewer User',
        role: 'viewer',
      });
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const badge = el.querySelector('[data-testid="role-badge-viewer"]');
      expect(badge).toBeTruthy();
      expect(badge!.textContent).toContain('Viewer');
    });

    it('should not display role badge when auth mode is none', () => {
      authService.authMode.set('none');
      authService.currentUser.set(null);
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const adminBadge = el.querySelector('[data-testid="role-badge-admin"]');
      const viewerBadge = el.querySelector('[data-testid="role-badge-viewer"]');
      expect(adminBadge).toBeFalsy();
      expect(viewerBadge).toBeFalsy();
    });

    it('should display user name when auth is enabled and user is logged in', () => {
      authService.authMode.set('oidc');
      authService.currentUser.set({
        id: 3,
        email: 'user@example.com',
        name: 'Test User',
        role: 'admin',
      });
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain('Test User');
    });

    it('should display user email when auth is enabled and user is logged in', () => {
      authService.authMode.set('local');
      authService.currentUser.set({
        id: 1,
        email: 'admin@example.com',
        name: 'Admin User',
        role: 'admin',
      });
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain('admin@example.com');
    });

    it('should use amber styling for admin badge', () => {
      authService.authMode.set('local');
      authService.currentUser.set({
        id: 1,
        email: 'admin@example.com',
        name: 'Admin User',
        role: 'admin',
      });
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const badge = el.querySelector('[data-testid="role-badge-admin"]');
      expect(badge).toBeTruthy();
      expect(badge!.className).toContain('bg-amber-500/20');
      expect(badge!.className).toContain('text-amber-300');
    });

    it('should use blue styling for viewer badge', () => {
      authService.authMode.set('local');
      authService.currentUser.set({
        id: 2,
        email: 'viewer@example.com',
        name: 'Viewer User',
        role: 'viewer',
      });
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const badge = el.querySelector('[data-testid="role-badge-viewer"]');
      expect(badge).toBeTruthy();
      expect(badge!.className).toContain('text-blue-300');
    });
  });
});
