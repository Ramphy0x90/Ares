import { Component, DestroyRef, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { filter, map, take } from 'rxjs';

@Component({
  selector: 'app-callback',
  standalone: true,
  template: `
    <div class="callback-container">
      <p>Signing you in...</p>
    </div>
  `,
  styles: [`
    .callback-container {
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: var(--colour-text-secondary, #888);
    }
  `],
})
export class CallbackComponent implements OnInit {
  private oidc = inject(OidcSecurityService);
  private router = inject(Router);
  private destroyRef = inject(DestroyRef);

  ngOnInit() {
    this.oidc.isAuthenticated$.pipe(
      map(result => result.isAuthenticated),
      filter(isAuthenticated => isAuthenticated),
      take(1),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(() => this.router.navigate(['/dashboard']));
  }
}
