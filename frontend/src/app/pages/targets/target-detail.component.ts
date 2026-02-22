import { Component, Inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { TargetService } from '../../core/services/target.service';
import { Target } from '../../core/models/target.model';

@Component({
  selector: 'app-target-dialog',
  standalone: true,
  imports: [CommonModule, FormsModule, MatDialogModule, MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule],
  template: `
    <h2 mat-dialog-title>{{ editing ? 'Edit Target' : 'Add Target' }}</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Name</mat-label>
        <input matInput [(ngModel)]="form.name" required>
      </mat-form-field>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Host / URL</mat-label>
        <input matInput [(ngModel)]="form.host" required placeholder="192.168.1.1 or https://example.com">
      </mat-form-field>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Type</mat-label>
        <mat-select [(ngModel)]="form.target_type">
          <mat-option value="host">Host</mat-option>
          <mat-option value="url">URL</mat-option>
          <mat-option value="api">API</mat-option>
          <mat-option value="llm_endpoint">LLM Endpoint</mat-option>
        </mat-select>
      </mat-form-field>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Description</mat-label>
        <textarea matInput [(ngModel)]="form.description" rows="3"></textarea>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-flat-button color="primary" (click)="save()" [disabled]="!form.name || !form.host">Save</button>
    </mat-dialog-actions>
  `,
  styles: [`.full-width { width: 100%; }`],
})
export class TargetDialogComponent implements OnInit {
  editing = false;
  form = { name: '', host: '', target_type: 'host', description: '' };

  constructor(
    private targetService: TargetService,
    private dialogRef: MatDialogRef<TargetDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: Target | null,
  ) {}

  ngOnInit(): void {
    if (this.data) {
      this.editing = true;
      this.form = { name: this.data.name, host: this.data.host, target_type: this.data.target_type, description: this.data.description || '' };
    }
  }

  save(): void {
    const obs = this.editing
      ? this.targetService.updateTarget(this.data!.id, this.form)
      : this.targetService.createTarget(this.form);
    obs.subscribe(result => this.dialogRef.close(result));
  }
}

// Re-export for the route
export { TargetDialogComponent as TargetDetailComponent };
