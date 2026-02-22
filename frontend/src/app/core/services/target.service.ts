import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import { Target, TargetCreate } from '../models/target.model';

@Injectable({ providedIn: 'root' })
export class TargetService {
  constructor(private api: ApiService) {}

  getTargets(params?: { search?: string; type?: string }): Observable<Target[]> {
    return this.api.get<Target[]>('/targets', params as Record<string, string>);
  }

  getTarget(id: number): Observable<Target> {
    return this.api.get<Target>(`/targets/${id}`);
  }

  createTarget(data: TargetCreate): Observable<Target> {
    return this.api.post<Target>('/targets', data);
  }

  updateTarget(id: number, data: Partial<TargetCreate>): Observable<Target> {
    return this.api.put<Target>(`/targets/${id}`, data);
  }

  deleteTarget(id: number): Observable<void> {
    return this.api.delete(`/targets/${id}`);
  }
}
