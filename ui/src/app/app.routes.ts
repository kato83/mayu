import { Routes } from '@angular/router';
import { LayoutComponent } from './layout/layout.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    title: $localize`:@@route.title.login:Sign In`,
    loadComponent: () =>
      import('./pages/login/login.component').then((m) => m.LoginComponent),
  },
  {
    path: '',
    component: LayoutComponent,
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      {
        path: 'dashboard',
        title: $localize`:@@route.title.dashboard:Dashboard`,
        loadComponent: () =>
          import('./pages/dashboard/dashboard.component').then(
            (m) => m.DashboardComponent,
          ),
      },
      {
        path: 'vulnerabilities',
        title: $localize`:@@route.title.vulnerabilities:Vulnerabilities`,
        loadComponent: () =>
          import('./pages/vulnerabilities/vulnerabilities.component').then(
            (m) => m.VulnerabilitiesComponent,
          ),
      },
      {
        path: 'vulnerabilities/:id',
        title: $localize`:@@route.title.vulnerabilityDetail:Vulnerability Detail`,
        loadComponent: () =>
          import('./pages/vulnerability-detail/vulnerability-detail.component').then(
            (m) => m.VulnerabilityDetailComponent,
          ),
      },
      {
        path: 'epss-trending',
        title: $localize`:@@route.title.epssTrending:EPSS Trending`,
        loadComponent: () =>
          import('./pages/epss-trending/epss-trending.component').then(
            (m) => m.EpssTrendingComponent,
          ),
      },
      {
        path: 'ingest/jobs',
        title: $localize`:@@route.title.ingestJobs:Ingest Jobs`,
        loadComponent: () =>
          import('./pages/ingest-jobs/ingest-jobs.component').then(
            (m) => m.IngestJobsComponent,
          ),
      },
      {
        path: 'ingest',
        title: $localize`:@@route.title.ingest:Ingest`,
        loadComponent: () =>
          import('./pages/ingest/ingest.component').then(
            (m) => m.IngestComponent,
          ),
      },
      {
        path: 'status',
        title: $localize`:@@route.title.status:Status`,
        loadComponent: () =>
          import('./pages/status/status.component').then(
            (m) => m.StatusComponent,
          ),
      },
      {
        path: 'webhooks',
        title: $localize`:@@route.title.webhooks:Webhooks`,
        loadComponent: () =>
          import('./pages/webhooks/webhooks.component').then(
            (m) => m.WebhooksComponent,
          ),
      },
      {
        path: 'webhooks/:id/deliveries',
        title: $localize`:@@route.title.webhookDeliveries:Webhook Deliveries`,
        loadComponent: () =>
          import('./pages/webhooks/webhook-deliveries.component').then(
            (m) => m.WebhookDeliveriesComponent,
          ),
      },
      {
        path: 'sbom',
        title: $localize`:@@route.title.sbom:SBOM Monitoring`,
        loadComponent: () =>
          import('./pages/sbom/sbom-projects.component').then(
            (m) => m.SbomProjectsComponent,
          ),
      },
      {
        path: 'sbom/:id',
        title: $localize`:@@route.title.sbomDetail:SBOM Project Detail`,
        loadComponent: () =>
          import('./pages/sbom/sbom-project-detail.component').then(
            (m) => m.SbomProjectDetailComponent,
          ),
      },
      {
        path: 'sbom/:projectId/scans/:scanId',
        title: $localize`:@@route.title.sbomScan:Scan Result`,
        loadComponent: () =>
          import('./pages/sbom/sbom-scan-detail.component').then(
            (m) => m.SbomScanDetailComponent,
          ),
      },
      {
        path: 'watchlists',
        title: $localize`:@@route.title.watchlists:Watchlists`,
        loadComponent: () =>
          import('./pages/watchlists/watchlists.component').then(
            (m) => m.WatchlistsComponent,
          ),
      },
      {
        path: 'teams',
        title: $localize`:@@route.title.teams:Teams`,
        loadComponent: () =>
          import('./pages/teams/teams.component').then(
            (m) => m.TeamsComponent,
          ),
      },
      {
        path: 'teams/:id',
        title: $localize`:@@route.title.teamDetail:Team Detail`,
        loadComponent: () =>
          import('./pages/teams/team-detail.component').then(
            (m) => m.TeamDetailComponent,
          ),
      },
      {
        path: 'api-keys',
        title: $localize`:@@route.title.apiKeys:API Keys`,
        loadComponent: () =>
          import('./pages/api-keys/api-keys.component').then(
            (m) => m.ApiKeysComponent,
          ),
      },
      {
        path: 'docs',
        redirectTo: 'docs/readme',
        pathMatch: 'full',
      },
      {
        path: 'docs/:slug',
        title: $localize`:@@route.title.docs:Docs`,
        loadComponent: () =>
          import('./pages/docs/docs.component').then(
            (m) => m.DocsComponent,
          ),
      },
    ],
  },
];
