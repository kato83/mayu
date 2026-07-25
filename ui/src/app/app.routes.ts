import { Routes } from '@angular/router';
import { LayoutComponent } from './layout/layout.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () =>
      import('./pages/login/login.component').then((m) => m.LoginComponent),
  },
  {
    path: '',
    component: LayoutComponent,
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'vulnerabilities', pathMatch: 'full' },
      {
        path: 'vulnerabilities',
        loadComponent: () =>
          import('./pages/vulnerabilities/vulnerabilities.component').then(
            (m) => m.VulnerabilitiesComponent,
          ),
      },
      {
        path: 'vulnerabilities/:id',
        loadComponent: () =>
          import('./pages/vulnerability-detail/vulnerability-detail.component').then(
            (m) => m.VulnerabilityDetailComponent,
          ),
      },
      {
        path: 'ingest/jobs',
        loadComponent: () =>
          import('./pages/ingest-jobs/ingest-jobs.component').then(
            (m) => m.IngestJobsComponent,
          ),
      },
      {
        path: 'ingest',
        loadComponent: () =>
          import('./pages/ingest/ingest.component').then(
            (m) => m.IngestComponent,
          ),
      },
      {
        path: 'status',
        loadComponent: () =>
          import('./pages/status/status.component').then(
            (m) => m.StatusComponent,
          ),
      },
      {
        path: 'webhooks',
        loadComponent: () =>
          import('./pages/webhooks/webhooks.component').then(
            (m) => m.WebhooksComponent,
          ),
      },
      {
        path: 'webhooks/:id/deliveries',
        loadComponent: () =>
          import('./pages/webhooks/webhook-deliveries.component').then(
            (m) => m.WebhookDeliveriesComponent,
          ),
      },
      {
        path: 'watchlists',
        loadComponent: () =>
          import('./pages/watchlists/watchlists.component').then(
            (m) => m.WatchlistsComponent,
          ),
      },
      {
        path: 'api-keys',
        loadComponent: () =>
          import('./pages/api-keys/api-keys.component').then(
            (m) => m.ApiKeysComponent,
          ),
      },
    ],
  },
];
