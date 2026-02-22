import { Component, Input } from '@angular/core';
import { MatProgressBarModule } from '@angular/material/progress-bar';

@Component({
  selector: 'app-scan-progress',
  standalone: true,
  imports: [MatProgressBarModule],
  template: `
    <div class="progress-container">
      <mat-progress-bar [mode]="progress < 0 ? 'indeterminate' : 'determinate'" [value]="progress * 100"></mat-progress-bar>
      <span class="progress-label">{{ (progress * 100).toFixed(0) }}%</span>
    </div>
  `,
  styles: [`
    .progress-container { display: flex; align-items: center; gap: 8px; }
    .progress-label { font-size: 12px; color: var(--colour-muted-foreground); min-width: 36px; }
  `],
})
export class ScanProgressComponent {
  @Input() progress: number = 0;
}
