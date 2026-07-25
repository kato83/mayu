import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { LOCALE_ID } from '@angular/core';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DocsService } from './docs.service';

describe('DocsService', () => {
  describe('with English locale', () => {
    let service: DocsService;
    let httpTesting: HttpTestingController;

    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          { provide: LOCALE_ID, useValue: 'en' },
        ],
      });

      service = TestBed.inject(DocsService);
      httpTesting = TestBed.inject(HttpTestingController);
    });

    afterEach(() => {
      httpTesting.verify();
    });

    it('should fetch the English document directly', () => {
      let result = '';
      service.getDocument('readme').subscribe((md) => (result = md));

      const req = httpTesting.expectOne('docs/README.md');
      req.flush('# English README');

      expect(result).toBe('# English README');
    });

    it('should return empty string for unknown slug', () => {
      let result: string | undefined;
      service.getDocument('nonexistent').subscribe((md) => (result = md));

      expect(result).toBe('');
    });
  });

  describe('with Japanese locale', () => {
    let service: DocsService;
    let httpTesting: HttpTestingController;

    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          { provide: LOCALE_ID, useValue: 'ja' },
        ],
      });

      service = TestBed.inject(DocsService);
      httpTesting = TestBed.inject(HttpTestingController);
    });

    afterEach(() => {
      httpTesting.verify();
    });

    it('should try Japanese variant first and use it if available', () => {
      let result = '';
      service.getDocument('readme').subscribe((md) => (result = md));

      const req = httpTesting.expectOne('docs/README_ja.md');
      req.flush('# Japanese README');

      expect(result).toBe('# Japanese README');
    });

    it('should fall back to English when Japanese variant returns 404', () => {
      let result = '';
      service.getDocument('readme').subscribe((md) => (result = md));

      // First request: Japanese variant fails
      const jaReq = httpTesting.expectOne('docs/README_ja.md');
      jaReq.flush('Not Found', { status: 404, statusText: 'Not Found' });

      // Second request: falls back to English
      const enReq = httpTesting.expectOne('docs/README.md');
      enReq.flush('# English README');

      expect(result).toBe('# English README');
    });

    it('should fetch English version for documents without Japanese variant', () => {
      let result = '';
      service.getDocument('import-ghsa-json').subscribe((md) => (result = md));

      const req = httpTesting.expectOne('docs/docs/import-ghsa-json.md');
      req.flush('# Import GHSA JSON');

      expect(result).toBe('# Import GHSA JSON');
    });
  });
});
