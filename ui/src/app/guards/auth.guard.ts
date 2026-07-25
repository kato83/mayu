import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // If auth mode is 'none', always allow access
  if (authService.authMode() === 'none') {
    return true;
  }

  // If auth mode is still unknown (config not loaded), treat as unauthenticated
  if (authService.authMode() === 'unknown') {
    return router.createUrlTree(['/login']);
  }

  // If authenticated, allow access
  if (authService.isAuthenticated()) {
    return true;
  }

  // Redirect to login page
  return router.createUrlTree(['/login']);
};
