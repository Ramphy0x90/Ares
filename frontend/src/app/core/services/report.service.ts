import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import { Report, ReportCreate } from '../models/report.model';

@Injectable({ providedIn: 'root' })
export class ReportService {
  constructor(private api: ApiService) {}

  getReports(): Observable<Report[]> {
    return this.api.get<Report[]>('/reports');
  }

  getReport(id: number): Observable<Report> {
    return this.api.get<Report>(`/reports/${id}`);
  }

  generateReport(data: ReportCreate): Observable<Report> {
    return this.api.post<Report>('/reports', data);
  }

  downloadReport(id: number): Observable<Blob> {
    return this.api.download(`/reports/${id}/download`);
  }
}
