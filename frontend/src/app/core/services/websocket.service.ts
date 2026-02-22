import { Injectable } from '@angular/core';
import { Observable, Subject, retry, timer } from 'rxjs';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';
import { environment } from '../../../environments/environment';

export interface ScanEvent {
  type: 'scanner_start' | 'finding' | 'scanner_complete' | 'scan_complete';
  scanner?: string;
  progress?: number;
  data?: unknown;
}

@Injectable({ providedIn: 'root' })
export class WebSocketService {
  private sockets = new Map<number, WebSocketSubject<ScanEvent>>();

  connect(scanId: number): Observable<ScanEvent> {
    if (!this.sockets.has(scanId)) {
      const ws = webSocket<ScanEvent>(`${environment.wsUrl}/ws/${scanId}`);
      this.sockets.set(scanId, ws);
    }
    return this.sockets.get(scanId)!.pipe(
      retry({ delay: () => timer(3000) })
    );
  }

  disconnect(scanId: number): void {
    const ws = this.sockets.get(scanId);
    if (ws) {
      ws.complete();
      this.sockets.delete(scanId);
    }
  }
}
