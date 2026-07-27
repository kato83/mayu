import { HttpInterceptorFn } from '@angular/common/http';
import { inject, LOCALE_ID } from '@angular/core';

/**
 * HTTP interceptor that adds the Accept-Language header to all outgoing API requests.
 * When the locale is not English, it sends the locale as primary preference
 * with English as a fallback (q=0.5).
 */
export const acceptLanguageInterceptor: HttpInterceptorFn = (req, next) => {
  const localeId = inject(LOCALE_ID);

  if (!req.url.startsWith('/api/') || isEnglish(localeId)) {
    return next(req);
  }

  const cloned = req.clone({
    setHeaders: {
      'Accept-Language': `${localeId},en;q=0.5`,
    },
  });

  return next(cloned);
};

function isEnglish(locale: string): boolean {
  const lower = locale.toLowerCase();
  return lower === 'en' || lower.startsWith('en-');
}
