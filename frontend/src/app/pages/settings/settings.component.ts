import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule, MatCardModule, MatFormFieldModule, MatInputModule, MatSlideToggleModule, MatButtonModule, MatSnackBarModule],
  template: `
    <div class="page-container">
      <div class="page-header"><h1>Settings</h1></div>

      <mat-card>
        <mat-card-header><mat-card-title>API Configuration</mat-card-title></mat-card-header>
        <mat-card-content>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Backend URL</mat-label>
            <input matInput [(ngModel)]="settings.apiUrl">
          </mat-form-field>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Max Concurrent Scans</mat-label>
            <input matInput type="number" [(ngModel)]="settings.maxConcurrentScans">
          </mat-form-field>
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Scan Timeout (seconds)</mat-label>
            <input matInput type="number" [(ngModel)]="settings.scanTimeout">
          </mat-form-field>
        </mat-card-content>
      </mat-card>

      <mat-card style="margin-top: 16px;">
        <mat-card-header><mat-card-title>Scanner Defaults</mat-card-title></mat-card-header>
        <mat-card-content>
          <div class="toggle-list">
            <mat-slide-toggle [(ngModel)]="settings.enableNetwork">Network Scanner</mat-slide-toggle>
            <mat-slide-toggle [(ngModel)]="settings.enableWebVuln">Web Vulnerability Scanner</mat-slide-toggle>
            <mat-slide-toggle [(ngModel)]="settings.enableSSL">SSL/TLS Analyzer</mat-slide-toggle>
            <mat-slide-toggle [(ngModel)]="settings.enableAPI">API Security Scanner</mat-slide-toggle>
            <mat-slide-toggle [(ngModel)]="settings.enableLLM">LLM Security Scanner</mat-slide-toggle>
            <mat-slide-toggle [(ngModel)]="settings.enableCredential">Credential Tester</mat-slide-toggle>
          </div>
        </mat-card-content>
      </mat-card>

      <div style="margin-top: 16px; text-align: right;">
        <button mat-flat-button color="primary" (click)="save()">Save Settings</button>
      </div>
    </div>
  `,
  styles: [`
    .full-width { width: 100%; }
    .toggle-list { display: flex; flex-direction: column; gap: 16px; }
  `],
})
export class SettingsComponent implements OnInit {
  settings = {
    apiUrl: 'http://localhost:8000/api/v1',
    maxConcurrentScans: 5,
    scanTimeout: 3600,
    enableNetwork: true,
    enableWebVuln: true,
    enableSSL: false,
    enableAPI: false,
    enableLLM: false,
    enableCredential: false,
  };

  constructor(private snackBar: MatSnackBar) {}

  ngOnInit(): void {
    const saved = localStorage.getItem('ares-settings');
    if (saved) this.settings = { ...this.settings, ...JSON.parse(saved) };
  }

  save(): void {
    localStorage.setItem('ares-settings', JSON.stringify(this.settings));
    this.snackBar.open('Settings saved', 'OK', { duration: 2000 });
  }
}
