import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-severity-badge',
  standalone: true,
  template: `<span class="severity-badge" [class]="severity">{{ severity }}</span>`,
})
export class SeverityBadgeComponent {
  @Input() severity: string = 'info';
}
