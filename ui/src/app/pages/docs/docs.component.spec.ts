import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DocsComponent } from './docs.component';
import { DOCS_MANIFEST } from './docs-manifest';

describe('DocsComponent', () => {
  let fixture: ComponentFixture<DocsComponent>;
  let component: DocsComponent;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DocsComponent],
      providers: [
        provideRouter([
          { path: 'docs/:slug', component: DocsComponent },
        ]),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);

    fixture = TestBed.createComponent(DocsComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should create the component', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url.includes('docs/'));
    req.flush('# Hello');
    fixture.detectChanges();

    expect(component).toBeTruthy();
  });

  it('should display document list', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url.includes('docs/'));
    req.flush('# Test');
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const links = el.querySelectorAll('nav a');
    expect(links.length).toBe(DOCS_MANIFEST.length);
    expect(links[0].textContent?.trim()).toBe('README');
  });

  it('should show loading state initially', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Loading document...');

    const req = httpTesting.expectOne((r) => r.url.includes('docs/'));
    req.flush('# Content');
  });

  it('should render markdown content after loading', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url.includes('docs/'));
    req.flush('# Hello World');
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const article = el.querySelector('article');
    expect(article).toBeTruthy();
    expect(article!.innerHTML).toContain('<h1');
    expect(article!.textContent).toContain('Hello World');
  });

  it('should show error state on fetch failure', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url.includes('docs/'));
    req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Failed to load document.');
  });

  it('should apply prose classes to content area', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) => r.url.includes('docs/'));
    req.flush('# Test');
    fixture.detectChanges();

    const article = fixture.nativeElement.querySelector('article');
    expect(article?.classList.contains('prose')).toBe(true);
    expect(article?.classList.contains('dark:prose-invert')).toBe(true);
  });
});
