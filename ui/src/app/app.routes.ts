import { Routes } from '@angular/router';
import { LayoutComponent } from './layout/layout.component';

export const routes: Routes = [
  {
    path: '',
    component: LayoutComponent,
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
        path: 'ingest',
        loadComponent: () =>
          import('./pages/ingest/ingest.component').then(
            (m) => m.IngestComponent,
          ),
      },
    ],
  },
];
