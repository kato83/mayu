import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { VulnerabilitiesComponent } from './vulnerabilities.component';
import { SearchResponse } from '../../models/vulnerability.model';

describe('VulnerabilitiesComponent', () => {
  let fixture: ComponentFixture<VulnerabilitiesComponent>;
  let component: VulnerabilitiesComponent;
  let httpTesting: HttpTestingController;
  let router: Router;

  const mockResponse: SearchResponse = {
    vulnerabilities: [
      {
        id: 'GO-2024-2687',
        modified: '2024-06-01T00:00:00Z',
        summary: 'Vulnerability in net/netip',
        affected: [{ package: { ecosystem: 'Go', name: 'net/netip' } }],
        severity: [{ type: 'CVSS_V3', score: 'CRITICAL' }],
      },
      {
        id: 'GO-2024-2688',
        modified: '2024-06-02T00:00:00Z',
        summary: 'Vulnerability in crypto',
        affected: [{ package: { ecosystem: 'Go', name: 'golang.org/x/crypto' } }],
      },
    ],
    total: 42,
    limit: 20,
    offset: 0,
    next_cursor: 'djF8MjAyNC0wNi0wMlQwMDowMDowMFp8R08tMjAyNC0yNjg4',
  };

  const emptyResponse: SearchResponse = {
    vulnerabilities: [],
    total: 0,
    limit: 20,
    offset: 0,
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [VulnerabilitiesComponent],
      providers: [
        provideRouter([
          { path: 'vulnerabilities', component: VulnerabilitiesComponent },
          { path: 'vulnerabilities/:id', component: VulnerabilitiesComponent },
        ]),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    router = TestBed.inject(Router);
    httpTesting = TestBed.inject(HttpTestingController);

    fixture = TestBed.createComponent(VulnerabilitiesComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  function initAndFlush(response: SearchResponse = mockResponse): void {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    req.flush(response);
    fixture.detectChanges();
  }

  // --- Basic rendering ---

  it('should create the component', () => {
    initAndFlush();
    expect(component).toBeTruthy();
  });

  it('should show loading state initially', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Loading vulnerabilities...');

    const req = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    req.flush(mockResponse);
  });

  it('should display vulnerabilities after loading', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('GO-2024-2687');
    expect(el.textContent).toContain('Vulnerability in net/netip');
    expect(el.textContent).toContain('Go');
  });

  it('should display severity badges', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('CRITICAL');
  });

  it('should show error state on API failure', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    req.flush({ error: 'internal server error' }, { status: 500, statusText: 'Internal Server Error' });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('internal server error');
  });

  it('should show empty state when no results', () => {
    initAndFlush(emptyResponse);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('No vulnerabilities found');
  });

  // --- Default behavior ---

  it('should load all vulnerabilities by default when no filters set', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    expect(req.request.params.has('ecosystem')).toBe(false);
    expect(req.request.params.get('limit')).toBe('20');
    // No cursor on first page
    expect(req.request.params.has('cursor')).toBe(false);
    req.flush(mockResponse);
  });

  // --- Pagination ---

  it('should display pagination when results exist', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Page 1 of 3');
    expect(el.textContent).toContain('42');
  });

  it('should use cursor for next page navigation', () => {
    initAndFlush();

    // Simulate clicking Next
    component.onPageChange({ direction: 'next' });

    const req = httpTesting.expectOne((r) =>
      r.url === '/api/v1/vulnerabilities' && r.params.has('cursor'),
    );
    expect(req.request.params.get('cursor')).toBe('djF8MjAyNC0wNi0wMlQwMDowMDowMFp8R08tMjAyNC0yNjg4');
    req.flush({ ...mockResponse, next_cursor: 'nextCursor2' });
    fixture.detectChanges();

    expect(component.currentPage()).toBe(2);
  });

  it('should go back to previous page using cursor stack', () => {
    initAndFlush();

    // Navigate to page 2
    component.onPageChange({ direction: 'next' });
    const req2 = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    req2.flush({ ...mockResponse, next_cursor: 'nextCursor2' });
    fixture.detectChanges();
    expect(component.currentPage()).toBe(2);

    // Navigate back to page 1
    component.onPageChange({ direction: 'previous' });
    const req1 = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    // First page has no cursor
    expect(req1.request.params.has('cursor')).toBe(false);
    req1.flush(mockResponse);
    fixture.detectChanges();

    expect(component.currentPage()).toBe(1);
  });

  it('should navigate to detail page on row click', () => {
    initAndFlush();
    const navigateSpy = vi.spyOn(router, 'navigate');
    const firstRow = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    firstRow.click();
    expect(navigateSpy).toHaveBeenCalledWith(['/vulnerabilities', 'GO-2024-2687']);
  });

  // --- Filter panel rendering ---

  it('should render filter panel with all inputs', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;

    expect(el.querySelector('#filter-id')).toBeTruthy();
    expect(el.querySelector('#filter-package')).toBeTruthy();
    expect(el.querySelector('#filter-ecosystem')).toBeTruthy();
    expect(el.querySelector('#filter-severity')).toBeTruthy();
    expect(el.querySelector('#filter-version')).toBeTruthy();
    expect(el.querySelector('#filter-since')).toBeTruthy();
  });

  it('should have ecosystem dropdown with options', () => {
    initAndFlush();
    const select = fixture.nativeElement.querySelector('#filter-ecosystem') as HTMLSelectElement;
    expect(select.options.length).toBeGreaterThan(5);
    expect(select.options[0].textContent).toContain('All ecosystems');
    expect(select.options[1].value).toBe('Go');
  });

  it('should have severity dropdown with options', () => {
    initAndFlush();
    const select = fixture.nativeElement.querySelector('#filter-severity') as HTMLSelectElement;
    expect(select.options.length).toBe(6); // '' + critical + high + medium + low + none
    expect(select.options[0].textContent).toContain('All severities');
  });

  // --- Filter behavior ---

  it('should update filters on input change', async () => {
    vi.useFakeTimers();
    initAndFlush();

    component.onFilterChange('ecosystem', 'npm');
    vi.advanceTimersByTime(300); // debounce

    const req = httpTesting.expectOne((r) =>
      r.url === '/api/v1/vulnerabilities' && r.params.get('ecosystem') === 'npm',
    );
    expect(req.request.params.get('ecosystem')).toBe('npm');
    req.flush(emptyResponse);
    vi.useRealTimers();
  });

  it('should debounce rapid filter changes', async () => {
    vi.useFakeTimers();
    initAndFlush();

    component.onFilterChange('package', 'g');
    vi.advanceTimersByTime(100);
    component.onFilterChange('package', 'go');
    vi.advanceTimersByTime(100);
    component.onFilterChange('package', 'golang.org');
    vi.advanceTimersByTime(300); // debounce fires

    // Only one request should be made after debounce
    const req = httpTesting.expectOne((r) =>
      r.url === '/api/v1/vulnerabilities' && r.params.get('package') === 'golang.org',
    );
    req.flush(emptyResponse);
    vi.useRealTimers();
  });

  it('should reset pagination when filter changes', async () => {
    vi.useFakeTimers();
    initAndFlush();

    // First navigate to page 2
    component.onPageChange({ direction: 'next' });
    const req2 = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    req2.flush(mockResponse);
    expect(component.currentPage()).toBe(2);

    // Now change a filter - should reset to page 1
    component.onFilterChange('severity', 'high');
    vi.advanceTimersByTime(300);

    const req = httpTesting.expectOne((r) =>
      r.url === '/api/v1/vulnerabilities' && r.params.get('severity') === 'high',
    );
    // No cursor should be sent (first page)
    expect(req.request.params.has('cursor')).toBe(false);
    req.flush(emptyResponse);
    expect(component.currentPage()).toBe(1);
    vi.useRealTimers();
  });

  it('should clear all filters', () => {
    initAndFlush();

    // Set some filters
    component.filters = { ...component.filters, ecosystem: 'npm', severity: 'high', package: 'express' };

    // Clear all
    component.clearFilters();

    // Should immediately fire (no debounce for clear)
    const req = httpTesting.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    // When no filters, no ecosystem param is sent
    expect(req.request.params.has('ecosystem')).toBe(false);
    expect(req.request.params.has('severity')).toBe(false);
    expect(req.request.params.has('package')).toBe(false);
    req.flush(emptyResponse);
  });

  it('should send multiple filters simultaneously', async () => {
    vi.useFakeTimers();
    initAndFlush();

    component.onFilterChange('ecosystem', 'npm');
    component.onFilterChange('severity', 'critical');
    vi.advanceTimersByTime(300);

    const req = httpTesting.expectOne((r) =>
      r.url === '/api/v1/vulnerabilities' &&
      r.params.get('ecosystem') === 'npm' &&
      r.params.get('severity') === 'critical',
    );
    req.flush(emptyResponse);
    vi.useRealTimers();
  });

  // --- Clear button ---

  it('should have a clear filters button', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    const buttons = Array.from(el.querySelectorAll('button'));
    const clearButton = buttons.find((b) => b.textContent?.includes('Clear filters'));
    expect(clearButton).toBeTruthy();
  });
});
