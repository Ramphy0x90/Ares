import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { TargetService } from '../../core/services/target.service';
import { ScanService } from '../../core/services/scan.service';
import { Target } from '../../core/models/target.model';

@Component({
  selector: 'app-scan-launch',
  standalone: true,
  imports: [CommonModule, FormsModule, MatCardModule, MatFormFieldModule, MatSelectModule, MatCheckboxModule, MatButtonModule, MatIconModule, MatSnackBarModule],
  template: `
    <div class="page-container">
      <div class="page-header">
        <h1>Launch New Scan</h1>
      </div>

      <mat-card>
        <mat-card-content>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Select Target</mat-label>
            <mat-select [(ngModel)]="selectedTargetId" required>
              @for (t of targets; track t.id) {
                <mat-option [value]="t.id">{{ t.name }} ({{ t.host }})</mat-option>
              }
            </mat-select>
          </mat-form-field>

          <h3>Scanner Modules</h3>
          <div class="scanner-grid">
            @for (s of scannerModules; track s.id) {
              <mat-checkbox [(ngModel)]="s.selected" [color]="'primary'">
                <div class="scanner-option">
                  <strong>{{ s.label }}</strong>
                  <span class="scanner-desc">{{ s.description }}</span>
                </div>
              </mat-checkbox>
            }
          </div>

          <div class="launch-actions">
            <button mat-flat-button color="primary" (click)="launch()" [disabled]="!selectedTargetId || !hasSelectedScanner()">
              <mat-icon>play_arrow</mat-icon> Launch Scan
            </button>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .full-width { width: 100%; }
    .scanner-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 16px 0; }
    .scanner-option { display: flex; flex-direction: column; }
    .scanner-desc { font-size: 12px; color: var(--colour-muted-foreground); }
    .launch-actions { margin-top: 24px; text-align: right; }
  `],
})
export class ScanLaunchComponent implements OnInit {
  targets: Target[] = [];
  selectedTargetId: number | null = null;
  scannerModules = [
    { id: 'network', label: 'Network Scanner', description: 'Port scan, service detection, OS fingerprinting', selected: true },
    { id: 'web_vuln', label: 'Web Vulnerability', description: 'OWASP Top 10, SQLi, XSS, CORS checks', selected: true },
    { id: 'ssl', label: 'SSL/TLS Analyzer', description: 'Certificate, cipher suite, protocol analysis', selected: false },
    { id: 'api_security', label: 'API Security', description: 'BOLA, JWT analysis, rate limiting', selected: false },
    { id: 'llm_security', label: 'LLM Security', description: 'Prompt injection, jailbreak, data exfiltration', selected: false },
    { id: 'credential', label: 'Credential Tester', description: 'Default credentials, brute force testing', selected: false },
  ];

  constructor(private targetService: TargetService, private scanService: ScanService, private router: Router, private snackBar: MatSnackBar) {}

  ngOnInit(): void {
    this.targetService.getTargets().subscribe(t => this.targets = t);
  }

  hasSelectedScanner(): boolean {
    return this.scannerModules.some(s => s.selected);
  }

  launch(): void {
    const scanners = this.scannerModules.filter(s => s.selected).map(s => s.id);
    this.scanService.launchScan({ target_id: this.selectedTargetId!, scanners }).subscribe(scan => {
      this.snackBar.open('Scan launched successfully', 'OK', { duration: 3000 });
      this.router.navigate(['/scans', scan.id]);
    });
  }
}
