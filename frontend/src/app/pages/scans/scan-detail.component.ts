import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { Subscription } from 'rxjs';
import { Router } from '@angular/router';
import { ScanService } from '../../core/services/scan.service';
import { WebSocketService, ScanEvent } from '../../core/services/websocket.service';
import { Scan } from '../../core/models/scan.model';
import { Vulnerability } from '../../core/models/vulnerability.model';
import { ScanProgressComponent } from '../../shared/components/scan-progress.component';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge.component';

@Component({
  selector: 'app-scan-detail',
  standalone: true,
  imports: [CommonModule, RouterLink, MatCardModule, MatTableModule, MatButtonModule, MatIconModule, ScanProgressComponent, SeverityBadgeComponent],
  template: `
    <div class="page-container">
      @if (scan) {
        <div class="page-header">
          <h1>Scan #{{ scan.id }}</h1>
          <div style="display: flex; gap: 8px;">
            <a mat-flat-button [routerLink]="['/scans', scan.id, 'vulnerabilities']">
              <mat-icon>bug_report</mat-icon> All Vulnerabilities
            </a>
            @if (scan.status === 'running') {
              <button mat-flat-button color="warn" (click)="stop()">
                <mat-icon>stop</mat-icon> Stop Scan
              </button>
            }
            <button mat-flat-button color="warn" (click)="deleteScan()">
              <mat-icon>delete</mat-icon> Delete
            </button>
          </div>
        </div>

        <div class="card-grid">
          <div class="summary-card" style="border-color: var(--colour-info)">
            <div class="card-label">Status</div>
            <div><span class="status-chip" [class]="scan.status">{{ scan.status }}</span></div>
          </div>
          <div class="summary-card" style="border-color: var(--colour-primary)">
            <div class="card-label">Progress</div>
            <app-scan-progress [progress]="scan.progress" />
          </div>
          <div class="summary-card" style="border-color: var(--colour-warning)">
            <div class="card-label">Findings</div>
            <div class="card-value">{{ vulns.length }}</div>
          </div>
        </div>

        <div class="events-log">
          @for (evt of events; track $index) {
            <div class="event-item">
              <mat-icon [class]="evt.type === 'finding' ? 'severity-high' : ''">
                {{ evt.type === 'finding' ? 'warning' : evt.type === 'scanner_start' ? 'play_circle' : 'check_circle' }}
              </mat-icon>
              <span>{{ evt.type }} {{ evt.scanner ? '- ' + evt.scanner : '' }}</span>
            </div>
          }
        </div>

        <mat-card style="margin-top: 16px;">
          <mat-card-header><mat-card-title>Findings</mat-card-title></mat-card-header>
          <mat-card-content>
            <table mat-table [dataSource]="vulns" class="full-width-table">
              <ng-container matColumnDef="severity">
                <th mat-header-cell *matHeaderCellDef>Severity</th>
                <td mat-cell *matCellDef="let v"><app-severity-badge [severity]="v.severity" /></td>
              </ng-container>
              <ng-container matColumnDef="title">
                <th mat-header-cell *matHeaderCellDef>Title</th>
                <td mat-cell *matCellDef="let v">
                  <a [routerLink]="['/vulnerabilities', v.id]">{{ v.title }}</a>
                </td>
              </ng-container>
              <ng-container matColumnDef="scanner">
                <th mat-header-cell *matHeaderCellDef>Scanner</th>
                <td mat-cell *matCellDef="let v">{{ v.scanner_name }}</td>
              </ng-container>
              <ng-container matColumnDef="cvss">
                <th mat-header-cell *matHeaderCellDef>CVSS</th>
                <td mat-cell *matCellDef="let v">{{ v.cvss_score || '-' }}</td>
              </ng-container>
              <tr mat-header-row *matHeaderRowDef="vulnColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: vulnColumns;"></tr>
            </table>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .events-log {
      max-height: 200px; overflow-y: auto; border-radius: 8px; padding: 12px;
      background: var(--colour-card); border: 1px solid var(--colour-border);
    }
    .event-item { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 13px; color: var(--colour-muted-foreground); }
  `],
})
export class ScanDetailComponent implements OnInit, OnDestroy {
  @Input() id!: string;
  scan: Scan | null = null;
  vulns: Vulnerability[] = [];
  events: ScanEvent[] = [];
  vulnColumns = ['severity', 'title', 'scanner', 'cvss'];
  private wsSub?: Subscription;

  constructor(private scanService: ScanService, private wsService: WebSocketService, private router: Router) {}

  ngOnInit(): void {
    const scanId = Number(this.id);
    this.scanService.getScan(scanId).subscribe(s => {
      this.scan = s;
      if (s.status === 'running') {
        this.wsSub = this.wsService.connect(scanId).subscribe(evt => {
          this.events.push(evt);
          if (evt.progress !== undefined && this.scan) this.scan.progress = evt.progress;
          if (evt.type === 'finding') {
            this.scanService.getScanVulnerabilities(scanId).subscribe(v => this.vulns = v);
          }
          if (evt.type === 'scan_complete' && this.scan) { this.scan.status = 'completed'; this.scan.progress = 1.0; }
        });
      }
    });
    this.scanService.getScanVulnerabilities(scanId).subscribe(v => this.vulns = v);
  }

  stop(): void {
    if (this.scan) {
      this.scanService.stopScan(this.scan.id).subscribe(s => this.scan = s);
    }
  }

  deleteScan(): void {
    if (this.scan && confirm(`Delete Scan #${this.scan.id}? This will also delete all its findings.`)) {
      this.scanService.deleteScan(this.scan.id).subscribe(() => this.router.navigate(['/scans']));
    }
  }

  ngOnDestroy(): void {
    this.wsSub?.unsubscribe();
    if (this.scan) this.wsService.disconnect(this.scan.id);
  }
}
