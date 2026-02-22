import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import { Scan, ScanCreate, ScanConfig } from '../models/scan.model';
import { Vulnerability } from '../models/vulnerability.model';

@Injectable({ providedIn: 'root' })
export class ScanService {
  constructor(private api: ApiService) {}

  getScans(params?: { target_id?: string; status?: string }): Observable<Scan[]> {
    return this.api.get<Scan[]>('/scans', params as Record<string, string>);
  }

  getScan(id: number): Observable<Scan> {
    return this.api.get<Scan>(`/scans/${id}`);
  }

  launchScan(data: ScanCreate): Observable<Scan> {
    return this.api.post<Scan>('/scans', data);
  }

  stopScan(id: number): Observable<Scan> {
    return this.api.post<Scan>(`/scans/${id}/stop`, {});
  }

  getScanVulnerabilities(id: number): Observable<Vulnerability[]> {
    return this.api.get<Vulnerability[]>(`/scans/${id}/vulnerabilities`);
  }

  getScanConfigs(): Observable<ScanConfig[]> {
    return this.api.get<ScanConfig[]>('/scan-configs');
  }
}
