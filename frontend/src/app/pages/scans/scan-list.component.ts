import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { ScanService } from '../../core/services/scan.service';
import { Scan } from '../../core/models/scan.model';
import { ScanProgressComponent } from '../../shared/components/scan-progress.component';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-scan-list',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule, MatTableModule, MatButtonModule, MatIconModule, MatSelectModule, MatFormFieldModule, ScanProgressComponent, TimeAgoPipe],
  template: `
    <div class="page-container">
      <div class="page-header">
        <h1>Scans</h1>
        <button mat-flat-button color="primary" routerLink="/scans/launch">
          <mat-icon>play_arrow</mat-icon> Launch Scan
        </button>
      </div>

      <div class="filters">
        <mat-form-field appearance="outline">
          <mat-label>Status</mat-label>
          <mat-select [(ngModel)]="statusFilter" (ngModelChange)="load()">
            <mat-option value="">All</mat-option>
            <mat-option value="running">Running</mat-option>
            <mat-option value="completed">Completed</mat-option>
            <mat-option value="failed">Failed</mat-option>
            <mat-option value="pending">Pending</mat-option>
          </mat-select>
        </mat-form-field>
      </div>

      <table mat-table [dataSource]="scans" class="full-width-table">
        <ng-container matColumnDef="id">
          <th mat-header-cell *matHeaderCellDef>ID</th>
          <td mat-cell *matCellDef="let s">
            <a [routerLink]="['/scans', s.id]">#{{ s.id }}</a>
          </td>
        </ng-container>
        <ng-container matColumnDef="target">
          <th mat-header-cell *matHeaderCellDef>Target</th>
          <td mat-cell *matCellDef="let s">{{ s.target_id }}</td>
        </ng-container>
        <ng-container matColumnDef="status">
          <th mat-header-cell *matHeaderCellDef>Status</th>
          <td mat-cell *matCellDef="let s"><span class="status-chip" [class]="s.status">{{ s.status }}</span></td>
        </ng-container>
        <ng-container matColumnDef="progress">
          <th mat-header-cell *matHeaderCellDef>Progress</th>
          <td mat-cell *matCellDef="let s"><app-scan-progress [progress]="s.progress" /></td>
        </ng-container>
        <ng-container matColumnDef="created">
          <th mat-header-cell *matHeaderCellDef>Started</th>
          <td mat-cell *matCellDef="let s">{{ s.created_at | timeAgo }}</td>
        </ng-container>
        <ng-container matColumnDef="actions">
          <th mat-header-cell *matHeaderCellDef></th>
          <td mat-cell *matCellDef="let s">
            <button mat-icon-button color="warn" (click)="deleteScan(s, $event)">
              <mat-icon>delete</mat-icon>
            </button>
          </td>
        </ng-container>
        <tr mat-header-row *matHeaderRowDef="columns"></tr>
        <tr mat-row *matRowDef="let row; columns: columns;"></tr>
      </table>
    </div>
  `,
  styles: [`.filters { margin-bottom: 16px; } .filters mat-form-field { width: 200px; }`],
})
export class ScanListComponent implements OnInit {
  scans: Scan[] = [];
  columns = ['id', 'target', 'status', 'progress', 'created', 'actions'];
  statusFilter = '';

  constructor(private scanService: ScanService) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.scanService.getScans({ status: this.statusFilter }).subscribe(s => this.scans = s);
  }

  deleteScan(scan: Scan, event: Event): void {
    event.stopPropagation();
    if (confirm(`Delete Scan #${scan.id}? This will also delete all its findings.`)) {
      this.scanService.deleteScan(scan.id).subscribe(() => this.load());
    }
  }
}
