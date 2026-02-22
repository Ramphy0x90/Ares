import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { MatTableModule } from '@angular/material/table';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatSortModule, Sort } from '@angular/material/sort';
import { VulnerabilityService } from '../../core/services/vulnerability.service';
import { Vulnerability } from '../../core/models/vulnerability.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge.component';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-vuln-list',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule, MatTableModule, MatFormFieldModule, MatSelectModule, MatSortModule, SeverityBadgeComponent, TimeAgoPipe],
  template: `
    <div class="page-container">
      <div class="page-header"><h1>Vulnerabilities</h1></div>

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
      </div>

      <table mat-table [dataSource]="vulns" matSort (matSortChange)="sortData($event)" class="full-width-table">
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
  vulns: Vulnerability[] = [];
  columns = ['severity', 'title', 'scanner_name', 'cvss_score', 'status', 'created_at'];
  filters = { severity: '', status: '', scanner: '' };

  constructor(private vulnService: VulnerabilityService) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.vulnService.getVulnerabilities(this.filters).subscribe(v => this.vulns = v);
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
