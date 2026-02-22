import { Component, OnInit, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { VulnerabilityService } from '../../core/services/vulnerability.service';
import { Vulnerability } from '../../core/models/vulnerability.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge.component';

@Component({
  selector: 'app-vuln-detail',
  standalone: true,
  imports: [CommonModule, FormsModule, MatCardModule, MatButtonModule, MatSelectModule, MatFormFieldModule, MatIconModule, MatSnackBarModule, SeverityBadgeComponent],
  template: `
    <div class="page-container">
      @if (vuln) {
        <div class="page-header">
          <h1>{{ vuln.title }}</h1>
          <app-severity-badge [severity]="vuln.severity" />
        </div>

        <div class="card-grid">
          <div class="summary-card" style="border-color: var(--colour-primary)">
            <div class="card-label">Scanner</div>
            <div>{{ vuln.scanner_name }}</div>
          </div>
          <div class="summary-card" style="border-color: var(--colour-warning)">
            <div class="card-label">CVSS Score</div>
            <div class="card-value">{{ vuln.cvss_score ?? 'N/A' }}</div>
          </div>
          <div class="summary-card" style="border-color: var(--colour-info)">
            <div class="card-label">CWE</div>
            <div>{{ vuln.cwe_id || 'N/A' }}</div>
          </div>
          <div class="summary-card" style="border-color: var(--colour-success)">
            <div class="card-label">Component</div>
            <div>{{ vuln.affected_component || 'N/A' }}</div>
          </div>
        </div>

        <mat-card>
          <mat-card-header><mat-card-title>Description</mat-card-title></mat-card-header>
          <mat-card-content><p>{{ vuln.description }}</p></mat-card-content>
        </mat-card>

        @if (vuln.evidence) {
          <mat-card style="margin-top: 16px;">
            <mat-card-header><mat-card-title>Evidence</mat-card-title></mat-card-header>
            <mat-card-content><pre class="evidence-block">{{ vuln.evidence }}</pre></mat-card-content>
          </mat-card>
        }

        @if (vuln.remediation) {
          <mat-card style="margin-top: 16px;">
            <mat-card-header><mat-card-title>Remediation</mat-card-title></mat-card-header>
            <mat-card-content><p>{{ vuln.remediation }}</p></mat-card-content>
          </mat-card>
        }

        <mat-card style="margin-top: 16px;">
          <mat-card-content>
            <div style="display: flex; align-items: center; gap: 12px;">
              <mat-form-field appearance="outline">
                <mat-label>Status</mat-label>
                <mat-select [(ngModel)]="vuln.status" (ngModelChange)="updateStatus()">
                  <mat-option value="open">Open</mat-option>
                  <mat-option value="confirmed">Confirmed</mat-option>
                  <mat-option value="false_positive">False Positive</mat-option>
                  <mat-option value="remediated">Remediated</mat-option>
                </mat-select>
              </mat-form-field>
            </div>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .evidence-block {
      background: var(--colour-background); padding: 16px; border-radius: 8px;
      border: 1px solid var(--colour-border);
      font-family: 'Courier New', monospace; font-size: 13px;
      overflow-x: auto; white-space: pre-wrap; color: var(--colour-primary);
    }
  `],
})
export class VulnDetailComponent implements OnInit {
  @Input() id!: string;
  vuln: Vulnerability | null = null;

  constructor(private vulnService: VulnerabilityService, private snackBar: MatSnackBar) {}

  ngOnInit(): void {
    this.vulnService.getVulnerability(Number(this.id)).subscribe(v => this.vuln = v);
  }

  updateStatus(): void {
    if (this.vuln) {
      this.vulnService.updateStatus(this.vuln.id, this.vuln.status).subscribe(() => {
        this.snackBar.open('Status updated', 'OK', { duration: 2000 });
      });
    }
  }
}
