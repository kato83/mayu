import { ApplicationConfig, provideBrowserGlobalErrorListeners, APP_INITIALIZER, inject, Injectable } from '@angular/core';
import { provideRouter, TitleStrategy, RouterStateSnapshot } from '@angular/router';
import { Title } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import { routes } from './app.routes';
import { AuthService } from './services/auth.service';
import { acceptLanguageInterceptor } from './interceptors/accept-language.interceptor';
import { httpErrorInterceptor } from './interceptors/http-error.interceptor';

@Injectable()
class MayuTitleStrategy extends TitleStrategy {
  private readonly title = inject(Title);

  override updateTitle(snapshot: RouterStateSnapshot): void {
    const pageTitle = this.buildTitle(snapshot);
    this.title.setTitle(pageTitle ? `${pageTitle} | Mayu` : 'Mayu');
  }
}

function initializeAuth(): () => Promise<void> {
  const authService = inject(AuthService);
  return () => firstValueFrom(authService.init()).then(() => {});
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    { provide: TitleStrategy, useClass: MayuTitleStrategy },
    provideHttpClient(withInterceptors([acceptLanguageInterceptor, httpErrorInterceptor])),
    {
      provide: APP_INITIALIZER,
      useFactory: initializeAuth,
      multi: true,
    },
  ]
};
