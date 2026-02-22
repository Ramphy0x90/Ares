import { Component, inject } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [MatIconModule, MatButtonModule],
  template: `
    <div class="login-container">
      <div class="login-card">
        <mat-icon class="login-logo">security</mat-icon>
        <h1 class="login-title">ARES</h1>
        <p class="login-subtitle">Automated Reconnaissance & Exploitation System</p>
        <button mat-flat-button class="login-button" (click)="login()">
          <mat-icon>login</mat-icon>
          Sign in
        </button>
      </div>
    </div>
  `,
  styles: [`
    .login-container {
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100%;
    }
    .login-card {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      padding: 48px 64px;
      border-radius: 16px;
      border: 1px solid var(--colour-border, #333);
      background: var(--colour-surface, #1a1a1a);
    }
    .login-logo {
      font-size: 64px;
      width: 64px;
      height: 64px;
      color: var(--colour-primary, #10b981);
    }
    .login-title {
      margin: 0;
      font-size: 32px;
      font-weight: 700;
      letter-spacing: 6px;
      color: var(--colour-primary, #10b981);
    }
    .login-subtitle {
      margin: 0 0 24px;
      font-size: 13px;
      color: var(--colour-text-secondary, #888);
    }
    .login-button {
      background: var(--colour-primary, #10b981) !important;
      color: #111 !important;
      font-weight: 600;
      padding: 0 32px;
      height: 44px;
      font-size: 14px;
    }
  `],
})
export class LoginComponent {
  private oidc = inject(OidcSecurityService);

  login() {
    this.oidc.authorize();
  }
}
