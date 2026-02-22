import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ReportService } from '../../core/services/report.service';
import { Report } from '../../core/models/report.model';
import { GenerateReportDialogComponent } from './report-view.component';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-report-list',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule, MatTableModule, MatButtonModule, MatIconModule, MatDialogModule, MatSnackBarModule, TimeAgoPipe],
  template: `
    <div class="page-container">
      <div class="page-header">
        <h1>Reports</h1>
        <button mat-flat-button color="primary" (click)="openGenerateDialog()">
          <mat-icon>add</mat-icon> Generate Report
        </button>
      </div>

      <table mat-table [dataSource]="reports" class="full-width-table">
        <ng-container matColumnDef="title">
          <th mat-header-cell *matHeaderCellDef>Title</th>
          <td mat-cell *matCellDef="let r">{{ r.title }}</td>
        </ng-container>
        <ng-container matColumnDef="scan_id">
          <th mat-header-cell *matHeaderCellDef>Scan</th>
          <td mat-cell *matCellDef="let r"><a [routerLink]="['/scans', r.scan_id]">#{{ r.scan_id }}</a></td>
        </ng-container>
        <ng-container matColumnDef="format">
          <th mat-header-cell *matHeaderCellDef>Format</th>
          <td mat-cell *matCellDef="let r"><span class="type-badge" [class]="r.format">{{ r.format | uppercase }}</span></td>
        </ng-container>
        <ng-container matColumnDef="created_at">
          <th mat-header-cell *matHeaderCellDef>Created</th>
          <td mat-cell *matCellDef="let r">{{ r.created_at | timeAgo }}</td>
        </ng-container>
        <ng-container matColumnDef="actions">
          <th mat-header-cell *matHeaderCellDef></th>
          <td mat-cell *matCellDef="let r">
            <button mat-icon-button (click)="download(r)"><mat-icon>download</mat-icon></button>
          </td>
        </ng-container>
        <tr mat-header-row *matHeaderRowDef="columns"></tr>
        <tr mat-row *matRowDef="let row; columns: columns;"></tr>
      </table>
    </div>
  `,
})
export class ReportListComponent implements OnInit {
  reports: Report[] = [];
  columns = ['title', 'scan_id', 'format', 'created_at', 'actions'];

  constructor(private reportService: ReportService, private dialog: MatDialog, private snackBar: MatSnackBar) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.reportService.getReports().subscribe(r => this.reports = r);
  }

  openGenerateDialog(): void {
    const ref = this.dialog.open(GenerateReportDialogComponent, { width: '450px' });
    ref.afterClosed().subscribe(result => { if (result) this.load(); });
  }

  download(report: Report): void {
    this.reportService.downloadReport(report.id).subscribe(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.title}.${report.format}`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }
}
