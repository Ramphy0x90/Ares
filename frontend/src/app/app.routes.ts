import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';

export const routes: Routes = [
  { path: 'login', loadComponent: () => import('./pages/login/login.component').then(m => m.LoginComponent) },
  { path: 'callback', loadComponent: () => import('./pages/callback/callback.component').then(m => m.CallbackComponent) },
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard', loadComponent: () => import('./pages/dashboard/dashboard.component').then(m => m.DashboardComponent), canActivate: [authGuard] },
  { path: 'targets', loadComponent: () => import('./pages/targets/target-list.component').then(m => m.TargetListComponent), canActivate: [authGuard] },
  { path: 'targets/:id', loadComponent: () => import('./pages/targets/target-detail.component').then(m => m.TargetDetailComponent), canActivate: [authGuard] },
  { path: 'scans', loadComponent: () => import('./pages/scans/scan-list.component').then(m => m.ScanListComponent), canActivate: [authGuard] },
  { path: 'scans/launch', loadComponent: () => import('./pages/scans/scan-launch.component').then(m => m.ScanLaunchComponent), canActivate: [authGuard] },
  { path: 'scans/:id', loadComponent: () => import('./pages/scans/scan-detail.component').then(m => m.ScanDetailComponent), canActivate: [authGuard] },
  { path: 'vulnerabilities', loadComponent: () => import('./pages/vulnerabilities/vuln-list.component').then(m => m.VulnListComponent), canActivate: [authGuard] },
  { path: 'vulnerabilities/:id', loadComponent: () => import('./pages/vulnerabilities/vuln-detail.component').then(m => m.VulnDetailComponent), canActivate: [authGuard] },
  { path: 'reports', loadComponent: () => import('./pages/reports/report-list.component').then(m => m.ReportListComponent), canActivate: [authGuard] },
  { path: 'reports/:id', loadComponent: () => import('./pages/reports/report-view.component').then(m => m.ReportViewComponent), canActivate: [authGuard] },
  { path: 'settings', loadComponent: () => import('./pages/settings/settings.component').then(m => m.SettingsComponent), canActivate: [authGuard] },
];
