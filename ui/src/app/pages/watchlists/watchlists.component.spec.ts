import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { WatchlistsComponent } from './watchlists.component';
import { Watchlist, WatchlistMatchesResponse } from '../../models/watchlist.model';

describe('WatchlistsComponent', () => {
  let fixture: ComponentFixture<WatchlistsComponent>;
  let component: WatchlistsComponent;
  let httpTesting: HttpTestingController;

  const mockWatchlists: Watchlist[] = [
    {
      id: 1,
      user_id: 1,
      name: 'Go Crypto Watch',
      match_type: 'package',
      ecosystem: 'Go',
      package_name: 'golang.org/x/crypto',
      enabled: true,
      created_at: '2024-06-01T00:00:00Z',
      updated_at: '2024-06-01T00:00:00Z',
    },
    {
      id: 2,
      user_id: 1,
      name: 'Critical CVEs',
      match_type: 'ecosystem',
      ecosystem: 'npm',
      severity_min: 5,
      enabled: false,
      created_at: '2024-06-02T00:00:00Z',
      updated_at: '2024-06-02T00:00:00Z',
    },
  ];

  const mockMatchesResponse: WatchlistMatchesResponse = {
    matches: [
      {
        id: 1,
        watchlist_id: 1,
        vulnerability_id: 'CVE-2024-1234',
        matched_at: '2024-06-03T00:00:00Z',
        notified: true,
        notified_at: '2024-06-03T01:00:00Z',
      },
      {
        id: 2,
        watchlist_id: 1,
        vulnerability_id: 'GO-2024-5678',
        matched_at: '2024-06-04T00:00:00Z',
        notified: false,
      },
    ],
    total: 2,
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [WatchlistsComponent],
      providers: [
        provideRouter([
          { path: 'watchlists', component: WatchlistsComponent },
          { path: 'vulnerabilities/:id', component: WatchlistsComponent },
        ]),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(WatchlistsComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  function initAndFlush(watchlists: Watchlist[] = mockWatchlists): void {
    fixture.detectChanges();
    const req = httpTesting.expectOne('/api/v1/watchlists');
    req.flush(watchlists);
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
    expect(el.textContent).toContain('Loading...');
    const req = httpTesting.expectOne('/api/v1/watchlists');
    req.flush([]);
  });

  it('should display watchlists after loading', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Go Crypto Watch');
    expect(el.textContent).toContain('Critical CVEs');
    expect(el.textContent).toContain('package');
    expect(el.textContent).toContain('ecosystem');
  });

  it('should show empty state when no watchlists exist', () => {
    initAndFlush([]);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('No watchlists found');
  });

  it('should display enabled/disabled status', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Yes');
    expect(el.textContent).toContain('No');
  });

  it('should format conditions correctly', () => {
    initAndFlush();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('ecosystem: Go');
    expect(el.textContent).toContain('package: golang.org/x/crypto');
    expect(el.textContent).toContain('severity >= CRITICAL');
  });

  // --- Create form ---

  it('should show create form when button is clicked', () => {
    initAndFlush();
    component.onCreateNew();
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Create New Watchlist');
    expect(el.querySelector('#wlName')).toBeTruthy();
    expect(el.querySelector('#wlMatchType')).toBeTruthy();
  });

  it('should show ecosystem and package name fields for package match type', () => {
    initAndFlush();
    component.onCreateNew();
    component.formMatchType = 'package';
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('#wlEcosystem')).toBeTruthy();
    expect(el.querySelector('#wlPackageName')).toBeTruthy();
    expect(el.querySelector('#wlPurlPattern')).toBeFalsy();
    expect(el.querySelector('#wlCpePattern')).toBeFalsy();
  });

  it('should show purl field for purl match type', () => {
    initAndFlush();
    component.onCreateNew();
    component.formMatchType = 'purl';
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('#wlPurlPattern')).toBeTruthy();
    expect(el.querySelector('#wlEcosystem')).toBeFalsy();
    expect(el.querySelector('#wlPackageName')).toBeFalsy();
    expect(el.querySelector('#wlCpePattern')).toBeFalsy();
  });

  it('should show cpe field for cpe match type', () => {
    initAndFlush();
    component.onCreateNew();
    component.formMatchType = 'cpe';
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('#wlCpePattern')).toBeTruthy();
    expect(el.querySelector('#wlEcosystem')).toBeFalsy();
    expect(el.querySelector('#wlPackageName')).toBeFalsy();
    expect(el.querySelector('#wlPurlPattern')).toBeFalsy();
  });

  it('should show ecosystem field for ecosystem match type', () => {
    initAndFlush();
    component.onCreateNew();
    component.formMatchType = 'ecosystem';
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('#wlEcosystem')).toBeTruthy();
    expect(el.querySelector('#wlPackageName')).toBeFalsy();
    expect(el.querySelector('#wlPurlPattern')).toBeFalsy();
    expect(el.querySelector('#wlCpePattern')).toBeFalsy();
  });

  it('should submit create request', () => {
    initAndFlush();
    component.onCreateNew();
    component.formName = 'Test Watch';
    component.formMatchType = 'package';
    component.formEcosystem = 'Go';
    component.formPackageName = 'net/http';
    fixture.detectChanges();

    component.onSubmitForm();

    const req = httpTesting.expectOne('/api/v1/watchlists');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({
      name: 'Test Watch',
      match_type: 'package',
      ecosystem: 'Go',
      package_name: 'net/http',
    });
    req.flush({ id: 3, ...req.request.body, user_id: 1, enabled: true, created_at: '2024-06-05T00:00:00Z', updated_at: '2024-06-05T00:00:00Z' });

    // Should reload watchlists
    const listReq = httpTesting.expectOne('/api/v1/watchlists');
    listReq.flush(mockWatchlists);
  });

  it('should not submit if name is empty', () => {
    initAndFlush();
    component.onCreateNew();
    component.formName = '';
    fixture.detectChanges();

    component.onSubmitForm();

    httpTesting.expectNone('/api/v1/watchlists');
  });

  // --- Edit form ---

  it('should populate form when editing', () => {
    initAndFlush();
    component.onEdit(mockWatchlists[0]);
    fixture.detectChanges();

    expect(component.formName).toBe('Go Crypto Watch');
    expect(component.formMatchType).toBe('package');
    expect(component.formEcosystem).toBe('Go');
    expect(component.formPackageName).toBe('golang.org/x/crypto');
    expect(component.editingId()).toBe(1);
  });

  it('should show enabled checkbox when editing', () => {
    initAndFlush();
    component.onEdit(mockWatchlists[0]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('#wlEnabled')).toBeTruthy();
  });

  it('should submit update request', () => {
    initAndFlush();
    component.onEdit(mockWatchlists[0]);
    component.formName = 'Updated Watch';
    fixture.detectChanges();

    component.onSubmitForm();

    const req = httpTesting.expectOne('/api/v1/watchlists/1');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body.name).toBe('Updated Watch');
    expect(req.request.body.enabled).toBe(true);
    req.flush({ ...mockWatchlists[0], name: 'Updated Watch' });

    const listReq = httpTesting.expectOne('/api/v1/watchlists');
    listReq.flush(mockWatchlists);
  });

  // --- Delete ---

  it('should show confirmation dialog on delete', () => {
    initAndFlush();
    component.onDelete(mockWatchlists[0]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Are you sure you want to delete this watchlist?');
  });

  it('should delete watchlist on confirm', () => {
    initAndFlush();
    component.onDelete(mockWatchlists[0]);
    fixture.detectChanges();

    component.onConfirmDelete();

    const req = httpTesting.expectOne('/api/v1/watchlists/1');
    expect(req.request.method).toBe('DELETE');
    req.flush(null);

    const listReq = httpTesting.expectOne('/api/v1/watchlists');
    listReq.flush([mockWatchlists[1]]);
  });

  it('should cancel delete on dismiss', () => {
    initAndFlush();
    component.onDelete(mockWatchlists[0]);
    fixture.detectChanges();

    component.confirmDelete.set(null);
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).not.toContain('Are you sure you want to delete');
  });

  // --- Matches ---

  it('should load and display matches', () => {
    initAndFlush();
    component.onViewMatches(mockWatchlists[0]);

    const req = httpTesting.expectOne('/api/v1/watchlists/1/matches?limit=20&offset=0');
    expect(req.request.method).toBe('GET');
    req.flush(mockMatchesResponse);
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('CVE-2024-1234');
    expect(el.textContent).toContain('GO-2024-5678');
    expect(el.textContent).toContain('Total matches:');
  });

  it('should show no matches message when empty', () => {
    initAndFlush();
    component.onViewMatches(mockWatchlists[0]);

    const req = httpTesting.expectOne('/api/v1/watchlists/1/matches?limit=20&offset=0');
    req.flush({ matches: [], total: 0 });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('No matches found');
  });

  it('should have links to vulnerability detail pages', () => {
    initAndFlush();
    component.onViewMatches(mockWatchlists[0]);

    const req = httpTesting.expectOne('/api/v1/watchlists/1/matches?limit=20&offset=0');
    req.flush(mockMatchesResponse);
    fixture.detectChanges();

    const links = fixture.nativeElement.querySelectorAll('a[href*="/vulnerabilities/"]');
    expect(links.length).toBeGreaterThan(0);
    expect(links[0].getAttribute('href')).toBe('/vulnerabilities/CVE-2024-1234');
  });

  // --- Cancel form ---

  it('should hide form on cancel', () => {
    initAndFlush();
    component.onCreateNew();
    fixture.detectChanges();
    expect(component.showForm()).toBe(true);

    component.onCancelForm();
    fixture.detectChanges();
    expect(component.showForm()).toBe(false);
  });
});
