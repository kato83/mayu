import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { VersionService, VersionResponse } from './version.service';

describe('VersionService', () => {
  let service: VersionService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(VersionService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  describe('getVersion', () => {
    it('should send GET request to /api/v1/version', () => {
      const mockResponse: VersionResponse = { version: '1.2.3' };

      service.getVersion().subscribe((response) => {
        expect(response).toEqual(mockResponse);
        expect(response.version).toBe('1.2.3');
      });

      const req = httpTesting.expectOne('/api/v1/version');
      expect(req.request.method).toBe('GET');

      req.flush(mockResponse);
    });

    it('should return version string from the API', () => {
      const mockResponse: VersionResponse = { version: '0.1.0-dev' };

      service.getVersion().subscribe((response) => {
        expect(response.version).toBe('0.1.0-dev');
      });

      const req = httpTesting.expectOne('/api/v1/version');
      req.flush(mockResponse);
    });

    it('should propagate HTTP errors', () => {
      service.getVersion().subscribe({
        error: (error) => {
          expect(error.status).toBe(500);
        },
      });

      const req = httpTesting.expectOne('/api/v1/version');
      req.flush({ error: 'internal server error' }, { status: 500, statusText: 'Internal Server Error' });
    });

    it('should propagate 401 unauthorized errors', () => {
      service.getVersion().subscribe({
        error: (error) => {
          expect(error.status).toBe(401);
        },
      });

      const req = httpTesting.expectOne('/api/v1/version');
      req.flush({ error: 'unauthorized' }, { status: 401, statusText: 'Unauthorized' });
    });
  });
});
