import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { NgxChartsModule, Color, ScaleType } from '@swimlane/ngx-charts';
import { ApiService } from '../../core/services/api.service';
import { Vulnerability } from '../../core/models/vulnerability.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge.component';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

interface DashboardStats {
  total_targets: number;
  total_scans: number;
  active_scans: number;
  vuln_counts_by_severity: Record<string, number>;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink, MatCardModule, MatTableModule, MatIconModule, MatButtonModule, NgxChartsModule, SeverityBadgeComponent, TimeAgoPipe],
  template: `
    <div class="page-container">
      <div class="page-header">
        <h1>Dashboard</h1>
        <button mat-flat-button color="primary" routerLink="/scans/launch">
          <mat-icon>play_arrow</mat-icon> New Scan
        </button>
      </div>

      <div class="card-grid">
        <div class="summary-card" style="border-color: var(--colour-primary)">
          <div class="card-label">Total Targets</div>
          <div class="card-value">{{ stats?.total_targets || 0 }}</div>
        </div>
        <div class="summary-card" style="border-color: var(--colour-info)">
          <div class="card-label">Total Scans</div>
          <div class="card-value">{{ stats?.total_scans || 0 }}</div>
        </div>
        <div class="summary-card" style="border-color: var(--colour-warning)">
          <div class="card-label">Active Scans</div>
          <div class="card-value">{{ stats?.active_scans || 0 }}</div>
        </div>
        <div class="summary-card" style="border-color: var(--colour-destructive)">
          <div class="card-label">Critical Vulns</div>
          <div class="card-value severity-critical">{{ stats?.vuln_counts_by_severity?.['critical'] || 0 }}</div>
        </div>
      </div>

      <div class="charts-row">
        <mat-card class="chart-card">
          <mat-card-header><mat-card-title>Vulnerability Severity Distribution</mat-card-title></mat-card-header>
          <mat-card-content>
            @if (severityChartData.length) {
              <ngx-charts-pie-chart
                [results]="severityChartData"
                [view]="[400, 300]"
                [doughnut]="true"
                [scheme]="colorScheme"
                [labels]="true"
                [legend]="true"
                [legendTitle]="'Severity'"
              ></ngx-charts-pie-chart>
            } @else {
              <div class="no-data">No vulnerability data yet</div>
            }
          </mat-card-content>
        </mat-card>

        <mat-card class="findings-card">
          <mat-card-header><mat-card-title>Recent Findings</mat-card-title></mat-card-header>
          <mat-card-content>
            <table mat-table [dataSource]="recentFindings" class="full-width-table">
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
              <ng-container matColumnDef="time">
                <th mat-header-cell *matHeaderCellDef>Found</th>
                <td mat-cell *matCellDef="let v">{{ v.created_at | timeAgo }}</td>
              </ng-container>
              <tr mat-header-row *matHeaderRowDef="findingColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: findingColumns;"></tr>
            </table>
            @if (!recentFindings.length) {
              <div class="no-data">No findings yet. Launch a scan to get started.</div>
            }
          </mat-card-content>
        </mat-card>
      </div>
    </div>
  `,
  styles: [`
    .charts-row { display: grid; grid-template-columns: 1fr 2fr; gap: 16px; }
    .chart-card, .findings-card { background: var(--colour-card); border: 1px solid var(--colour-border); border-radius: 12px; }
    .no-data { padding: 40px; text-align: center; color: var(--colour-muted); }
    @media (max-width: 900px) { .charts-row { grid-template-columns: 1fr; } }
  `],
})
export class DashboardComponent implements OnInit {
  stats: DashboardStats | null = null;
  recentFindings: Vulnerability[] = [];
  severityChartData: { name: string; value: number }[] = [];
  findingColumns = ['severity', 'title', 'scanner', 'time'];
  colorScheme: Color = { name: 'severity', selectable: true, group: ScaleType.Ordinal, domain: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#a1a1aa'] };

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.get<DashboardStats>('/dashboard/stats').subscribe(stats => {
      this.stats = stats;
      const counts = stats.vuln_counts_by_severity;
      this.severityChartData = Object.entries(counts)
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value }));
    });
    this.api.get<Vulnerability[]>('/dashboard/recent-findings').subscribe(f => this.recentFindings = f);
  }
}
