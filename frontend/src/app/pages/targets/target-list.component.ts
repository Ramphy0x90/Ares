import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { TargetService } from '../../core/services/target.service';
import { Target } from '../../core/models/target.model';
import { ConfirmDialogComponent } from '../../shared/components/confirm-dialog.component';
import { TargetDialogComponent } from './target-detail.component';

@Component({
  selector: 'app-target-list',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule, MatTableModule, MatButtonModule, MatIconModule, MatInputModule, MatFormFieldModule, MatSelectModule, MatDialogModule, MatSnackBarModule],
  template: `
    <div class="page-container">
      <div class="page-header">
        <h1>Targets</h1>
        <button mat-flat-button color="primary" (click)="openDialog()">
          <mat-icon>add</mat-icon> Add Target
        </button>
      </div>

      <div class="filters">
        <mat-form-field appearance="outline">
          <mat-label>Search</mat-label>
          <input matInput [(ngModel)]="search" (ngModelChange)="loadTargets()" placeholder="Search targets...">
          <mat-icon matSuffix>search</mat-icon>
        </mat-form-field>
        <mat-form-field appearance="outline">
          <mat-label>Type</mat-label>
          <mat-select [(ngModel)]="typeFilter" (ngModelChange)="loadTargets()">
            <mat-option value="">All</mat-option>
            <mat-option value="host">Host</mat-option>
            <mat-option value="url">URL</mat-option>
            <mat-option value="api">API</mat-option>
            <mat-option value="llm_endpoint">LLM Endpoint</mat-option>
          </mat-select>
        </mat-form-field>
      </div>

      <table mat-table [dataSource]="targets" class="full-width-table">
        <ng-container matColumnDef="name">
          <th mat-header-cell *matHeaderCellDef>Name</th>
          <td mat-cell *matCellDef="let t">{{ t.name }}</td>
        </ng-container>
        <ng-container matColumnDef="host">
          <th mat-header-cell *matHeaderCellDef>Host</th>
          <td mat-cell *matCellDef="let t">{{ t.host }}</td>
        </ng-container>
        <ng-container matColumnDef="type">
          <th mat-header-cell *matHeaderCellDef>Type</th>
          <td mat-cell *matCellDef="let t"><span class="type-badge" [class]="t.target_type">{{ t.target_type }}</span></td>
        </ng-container>
        <ng-container matColumnDef="created">
          <th mat-header-cell *matHeaderCellDef>Created</th>
          <td mat-cell *matCellDef="let t">{{ t.created_at | date:'short' }}</td>
        </ng-container>
        <ng-container matColumnDef="actions">
          <th mat-header-cell *matHeaderCellDef></th>
          <td mat-cell *matCellDef="let t">
            <button mat-icon-button (click)="openDialog(t)"><mat-icon>edit</mat-icon></button>
            <button mat-icon-button color="warn" (click)="confirmDelete(t)"><mat-icon>delete</mat-icon></button>
          </td>
        </ng-container>
        <tr mat-header-row *matHeaderRowDef="columns"></tr>
        <tr mat-row *matRowDef="let row; columns: columns;"></tr>
      </table>
    </div>
  `,
  styles: [`
    .filters { display: flex; gap: 12px; margin-bottom: 16px; }
    .filters mat-form-field { width: 240px; }
  `],
})
export class TargetListComponent implements OnInit {
  targets: Target[] = [];
  columns = ['name', 'host', 'type', 'created', 'actions'];
  search = '';
  typeFilter = '';

  constructor(private targetService: TargetService, private dialog: MatDialog, private snackBar: MatSnackBar) {}

  ngOnInit(): void { this.loadTargets(); }

  loadTargets(): void {
    this.targetService.getTargets({ search: this.search, type: this.typeFilter }).subscribe(t => this.targets = t);
  }

  openDialog(target?: Target): void {
    const ref = this.dialog.open(TargetDialogComponent, { width: '500px', data: target || null });
    ref.afterClosed().subscribe(result => { if (result) this.loadTargets(); });
  }

  confirmDelete(target: Target): void {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      data: { title: 'Delete Target', message: `Delete "${target.name}" and all associated scans?`, confirmText: 'Delete' },
    });
    ref.afterClosed().subscribe(confirmed => {
      if (confirmed) {
        this.targetService.deleteTarget(target.id).subscribe(() => {
          this.snackBar.open('Target deleted', 'OK', { duration: 3000 });
          this.loadTargets();
        });
      }
    });
  }
}
