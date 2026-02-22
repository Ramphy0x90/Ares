import { Component, OnInit, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { forkJoin, of } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import { MatTableModule } from '@angular/material/table';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatSortModule, Sort } from '@angular/material/sort';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { VulnerabilityService } from '../../core/services/vulnerability.service';
import { ScanService } from '../../core/services/scan.service';
import { Vulnerability } from '../../core/models/vulnerability.model';
import { Scan } from '../../core/models/scan.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge.component';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-vuln-list',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule, MatTableModule, MatFormFieldModule, MatSelectModule, MatSortModule, MatCheckboxModule, MatProgressSpinnerModule, SeverityBadgeComponent, TimeAgoPipe],
  template: `
    <div class="page-container">
      <div class="page-header"><h1>Vulnerabilities{{ scanId ? ' — Scan #' + scanId : '' }}</h1></div>

      <div class="filters">
        <mat-form-field appearance="outline">
          <mat-label>Severity</mat-label>
          <mat-select [(ngModel)]="filters.severity" (ngModelChange)="load()">
            <mat-option value="">All</mat-option>
            <mat-option value="critical">Critical</mat-option>
            <mat-option value="high">High</mat-option>
            <mat-option value="medium">Medium</mat-option>
            <mat-option value="low">Low</mat-option>
            <mat-option value="info">Info</mat-option>
          </mat-select>
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Status</mat-label>
          <mat-select [(ngModel)]="filters.status" (ngModelChange)="load()">
            <mat-option value="">All</mat-option>
            <mat-option value="open">Open</mat-option>
            <mat-option value="confirmed">Confirmed</mat-option>
            <mat-option value="false_positive">False Positive</mat-option>
            <mat-option value="remediated">Remediated</mat-option>
          </mat-select>
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Scanner</mat-label>
          <mat-select [(ngModel)]="filters.scanner" (ngModelChange)="load()">
            <mat-option value="">All</mat-option>
            <mat-option value="network">Network</mat-option>
            <mat-option value="web_vuln">Web Vuln</mat-option>
            <mat-option value="ssl">SSL</mat-option>
            <mat-option value="api_security">API Security</mat-option>
            <mat-option value="llm_security">LLM Security</mat-option>
            <mat-option value="credential">Credential</mat-option>
          </mat-select>
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Scan</mat-label>
          <mat-select [(ngModel)]="filters.scan_id" (ngModelChange)="load()">
            <mat-option value="">All</mat-option>
            @for (s of scans; track s.id) {
              <mat-option [value]="'' + s.id">Scan #{{ s.id }}</mat-option>
            }
          </mat-select>
        </mat-form-field>
        <mat-checkbox [(ngModel)]="hasExploitsOnly" (ngModelChange)="load()" style="align-self: center;">
          Has known exploits
        </mat-checkbox>
      </div>

      @if (loading) {
        <div style="display: flex; align-items: center; gap: 12px; padding: 24px 0;">
          <mat-spinner diameter="24"></mat-spinner>
          <span>Loading vulnerabilities...</span>
        </div>
      }

      <table mat-table [dataSource]="vulns" [hidden]="loading" matSort (matSortChange)="sortData($event)" class="full-width-table">
        <ng-container matColumnDef="severity">
          <th mat-header-cell *matHeaderCellDef mat-sort-header>Severity</th>
          <td mat-cell *matCellDef="let v"><app-severity-badge [severity]="v.severity" /></td>
        </ng-container>
        <ng-container matColumnDef="title">
          <th mat-header-cell *matHeaderCellDef mat-sort-header>Title</th>
          <td mat-cell *matCellDef="let v">
            <a [routerLink]="['/vulnerabilities', v.id]">{{ v.title }}</a>
          </td>
        </ng-container>
        <ng-container matColumnDef="scanner_name">
          <th mat-header-cell *matHeaderCellDef mat-sort-header>Scanner</th>
          <td mat-cell *matCellDef="let v">{{ v.scanner_name }}</td>
        </ng-container>
        <ng-container matColumnDef="cvss_score">
          <th mat-header-cell *matHeaderCellDef mat-sort-header>CVSS</th>
          <td mat-cell *matCellDef="let v">{{ v.cvss_score ?? '-' }}</td>
        </ng-container>
        <ng-container matColumnDef="status">
          <th mat-header-cell *matHeaderCellDef mat-sort-header>Status</th>
          <td mat-cell *matCellDef="let v"><span class="status-chip" [class]="v.status">{{ v.status }}</span></td>
        </ng-container>
        <ng-container matColumnDef="created_at">
          <th mat-header-cell *matHeaderCellDef mat-sort-header>Found</th>
          <td mat-cell *matCellDef="let v">{{ v.created_at | timeAgo }}</td>
        </ng-container>
        <tr mat-header-row *matHeaderRowDef="columns"></tr>
        <tr mat-row *matRowDef="let row; columns: columns;"></tr>
      </table>
    </div>
  `,
  styles: [`.filters { display: flex; gap: 12px; margin-bottom: 16px; } .filters mat-form-field { width: 180px; }`],
})
export class VulnListComponent implements OnInit {
  @Input() scan_id?: string;
  scanId: string | null = null;
  scans: Scan[] = [];
  vulns: Vulnerability[] = [];
  hasExploitsOnly = false;
  loading = false;
  columns = ['severity', 'title', 'scanner_name', 'cvss_score', 'status', 'created_at'];
  filters: { severity: string; status: string; scanner: string; scan_id?: string } = { severity: '', status: '', scanner: '' };

  constructor(private vulnService: VulnerabilityService, private scanService: ScanService) {}

  ngOnInit(): void {
    if (this.scan_id) {
      this.scanId = this.scan_id;
      this.filters.scan_id = this.scan_id;
    }
    this.scanService.getScans().subscribe(s => this.scans = s);
    this.load();
  }

  load(): void {
    this.loading = true;
    this.vulnService.getVulnerabilities(this.filters).pipe(
      switchMap(vulns => {
        if (!this.hasExploitsOnly) {
          return of(vulns);
        }
        if (vulns.length === 0) return of([]);
        const checks = vulns.map(v => {
          const query = v.title.match(/CVE-\d{4}-\d+/i)?.[0] || v.cwe_id || v.affected_component || v.title.split(' ').slice(0, 3).join(' ');
          return this.vulnService.searchExploits(query).pipe(
            map(exploits => exploits.length > 0 ? v : null)
          );
        });
        return forkJoin(checks).pipe(
          map(results => results.filter((v): v is Vulnerability => v !== null))
        );
      })
    ).subscribe({
      next: v => { this.vulns = v; this.loading = false; },
      error: () => { this.loading = false; },
    });
  }

  sortData(sort: Sort): void {
    if (!sort.active || sort.direction === '') return;
    const data = [...this.vulns];
    this.vulns = data.sort((a, b) => {
      const asc = sort.direction === 'asc';
      const aVal = (a as unknown as Record<string, unknown>)[sort.active];
      const bVal = (b as unknown as Record<string, unknown>)[sort.active];
      if (aVal == null) return 1;
      if (bVal == null) return -1;
      return (aVal < bVal ? -1 : 1) * (asc ? 1 : -1);
    });
  }
}
