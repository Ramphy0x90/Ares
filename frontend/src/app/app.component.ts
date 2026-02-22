import { Component, computed, inject, OnInit } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatListModule } from '@angular/material/list';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterOutlet, RouterLink, RouterLinkActive,
    MatSidenavModule, MatToolbarModule, MatListModule,
    MatIconModule, MatButtonModule, MatMenuModule,
  ],
  template: `
    <mat-sidenav-container class="app-container">
      <mat-sidenav mode="side" [opened]="isAuthenticated()" class="app-sidenav">
        <div class="sidenav-header">
          <mat-icon class="logo-icon">security</mat-icon>
          <span class="logo-text">ARES</span>
        </div>
        <mat-nav-list>
          @for (item of navItems; track item.route) {
            <a mat-list-item [routerLink]="item.route" routerLinkActive="active-link">
              <mat-icon matListItemIcon>{{ item.icon }}</mat-icon>
              <span matListItemTitle>{{ item.label }}</span>
            </a>
          }
        </mat-nav-list>
      </mat-sidenav>
      <mat-sidenav-content>
        @if (isAuthenticated()) {
          <mat-toolbar class="app-toolbar">
            <span class="toolbar-spacer"></span>
            <button mat-button [matMenuTriggerFor]="userMenu" class="user-menu-trigger">
              <mat-icon>account_circle</mat-icon>
              <span>{{ userName() }}</span>
            </button>
            <mat-menu #userMenu="matMenu">
              <button mat-menu-item (click)="logout()">
                <mat-icon>logout</mat-icon>
                <span>Logout</span>
              </button>
            </mat-menu>
          </mat-toolbar>
        }
        <main class="app-content" [class.full-height]="!isAuthenticated()">
          <router-outlet />
        </main>
      </mat-sidenav-content>
    </mat-sidenav-container>
  `,
  styles: [`
    .app-container { height: 100vh; }
    .app-sidenav { width: 240px; border-right: 1px solid var(--colour-border); }
    .sidenav-header {
      display: flex; align-items: center; gap: 12px;
      padding: 20px 16px; border-bottom: 1px solid var(--colour-border);
    }
    .logo-icon { font-size: 32px; width: 32px; height: 32px; color: var(--colour-primary); }
    .logo-text { font-size: 22px; font-weight: 700; letter-spacing: 4px; color: var(--colour-primary); }
    .active-link {
      background: rgba(16, 185, 129, 0.1) !important;
      color: var(--colour-primary) !important;
      border-right: 2px solid var(--colour-primary);
    }
    .app-toolbar { height: 48px; }
    .toolbar-spacer { flex: 1; }
    .user-menu-trigger {
      display: flex; align-items: center; gap: 6px;
      color: var(--colour-text-secondary, #aaa);
      font-size: 13px;
    }
    .app-content { overflow-y: auto; height: calc(100vh - 48px); }
    .app-content.full-height { height: 100vh; }
  `],
})
export class AppComponent implements OnInit {
  private oidc = inject(OidcSecurityService);
  private authResult = toSignal(this.oidc.isAuthenticated$);
  private userData = toSignal(this.oidc.userData$);

  isAuthenticated = computed(() => this.authResult()?.isAuthenticated ?? false);

  userName = computed(() => {
    const ud = this.userData()?.userData;
    return ud?.preferred_username || ud?.name || ud?.email || 'User';
  });

  navItems = [
    { route: '/dashboard', icon: 'dashboard', label: 'Dashboard' },
    { route: '/targets', icon: 'track_changes', label: 'Targets' },
    { route: '/scans', icon: 'radar', label: 'Scans' },
    { route: '/vulnerabilities', icon: 'bug_report', label: 'Vulnerabilities' },
    { route: '/reports', icon: 'description', label: 'Reports' },
    { route: '/settings', icon: 'settings', label: 'Settings' },
  ];

  ngOnInit() {
    this.oidc.checkAuth().subscribe();
  }

  logout() {
    this.oidc.logoff().subscribe();
  }
}
