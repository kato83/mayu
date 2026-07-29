import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  APP_INITIALIZER,
  type ApplicationConfig,
  Injectable,
  inject,
  provideBrowserGlobalErrorListeners,
} from '@angular/core';
import { Title } from '@angular/platform-browser';
import { provideRouter, type RouterStateSnapshot, TitleStrategy } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { routes } from './app.routes';
import { acceptLanguageInterceptor } from './interceptors/accept-language.interceptor';
import { httpErrorInterceptor } from './interceptors/http-error.interceptor';
import { AuthService } from './services/auth.service';

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
  ],
};
