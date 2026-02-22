import { HttpInterceptorFn } from '@angular/common/http';
import { catchError, throwError } from 'rxjs';
import { environment } from '../../../environments/environment';

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  return next(req).pipe(
    catchError(error => {
      if (req.url.startsWith(environment.apiUrl)) {
        console.error('API Error:', error.status, error.message);
      }
      return throwError(() => error);
    })
  );
};
