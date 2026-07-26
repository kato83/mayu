import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';

import { ToastService } from '../shared/toast/toast.service';

/**
 * HTTP error interceptor that shows toast notifications for 4xx/5xx responses.
 * The error is still re-thrown so individual components can handle it if needed.
 */
export const httpErrorInterceptor: HttpInterceptorFn = (req, next) => {
  const toast = inject(ToastService);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status >= 400) {
        const message = extractErrorMessage(error);
        toast.error(message);
      }
      return throwError(() => error);
    }),
  );
};

/**
 * Extract a human-readable error message from the HTTP error response.
 */
function extractErrorMessage(error: HttpErrorResponse): string {
  // Try to extract a message from the response body
  if (error.error) {
    // API returns { "error": "message" } pattern
    if (typeof error.error === 'object' && error.error.error) {
      return `${error.status}: ${error.error.error}`;
    }
    // API returns { "message": "..." } pattern
    if (typeof error.error === 'object' && error.error.message) {
      return `${error.status}: ${error.error.message}`;
    }
    // Plain string response
    if (typeof error.error === 'string' && error.error.length < 200) {
      return `${error.status}: ${error.error}`;
    }
  }

  // Fall back to status text
  if (error.status === 0) {
    return $localize`:@@httpError.networkError:Network error — please check your connection.`;
  }

  return `${error.status}: ${error.statusText || 'Unknown error'}`;
}
