import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ReportService } from '../../core/services/report.service';
import { ScanService } from '../../core/services/scan.service';
import { Scan } from '../../core/models/scan.model';

@Component({
  selector: 'app-generate-report-dialog',
  standalone: true,
  imports: [CommonModule, FormsModule, MatDialogModule, MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule, MatSnackBarModule],
  template: `
    <h2 mat-dialog-title>Generate Report</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Title</mat-label>
        <input matInput [(ngModel)]="form.title" required>
      </mat-form-field>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Scan</mat-label>
        <mat-select [(ngModel)]="form.scan_id" required>
          @for (s of scans; track s.id) {
            <mat-option [value]="s.id">Scan #{{ s.id }} ({{ s.status }})</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Format</mat-label>
        <mat-select [(ngModel)]="form.format">
          <mat-option value="html">HTML</mat-option>
          <mat-option value="pdf">PDF</mat-option>
          <mat-option value="json">JSON</mat-option>
        </mat-select>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-flat-button color="primary" (click)="generate()" [disabled]="!form.title || !form.scan_id">Generate</button>
    </mat-dialog-actions>
  `,
  styles: [`.full-width { width: 100%; }`],
})
export class GenerateReportDialogComponent implements OnInit {
  scans: Scan[] = [];
  form = { title: '', scan_id: null as number | null, format: 'html' };

  constructor(
    private reportService: ReportService,
    private scanService: ScanService,
    private dialogRef: MatDialogRef<GenerateReportDialogComponent>,
    private snackBar: MatSnackBar,
  ) {}

  ngOnInit(): void {
    this.scanService.getScans({ status: 'completed' }).subscribe(s => this.scans = s);
  }

  generate(): void {
    this.reportService.generateReport({
      scan_id: this.form.scan_id!,
      title: this.form.title,
      format: this.form.format,
    }).subscribe(report => {
      this.snackBar.open('Report generated', 'OK', { duration: 3000 });
      this.dialogRef.close(report);
    });
  }
}

// Route alias
export { GenerateReportDialogComponent as ReportViewComponent };
