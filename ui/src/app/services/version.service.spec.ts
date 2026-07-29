import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { VersionResponse } from '../models/version.model';
import { VersionService } from './version.service';

describe('VersionService', () => {
  let service: VersionService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });

    service = TestBed.inject(VersionService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  describe('getVersion', () => {
    it('should send GET request to /api/v1/version', () => {
      const mockResponse: VersionResponse = {
        version: '1.2.3',
      };

      service.getVersion().subscribe((response) => {
        expect(response).toEqual(mockResponse);
        expect(response.version).toBe('1.2.3');
      });

      const req = httpTesting.expectOne('/api/v1/version');
      expect(req.request.method).toBe('GET');

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
  });
});
