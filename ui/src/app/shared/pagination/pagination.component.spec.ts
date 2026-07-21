import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Component, signal } from '@angular/core';
import { describe, it, expect, beforeEach } from 'vitest';

import { PaginationComponent, PageChangeEvent } from './pagination.component';

// Test host component to provide input signals
@Component({
  standalone: true,
  imports: [PaginationComponent],
  template: `
    <app-pagination
      [total]="total()"
      [limit]="limit()"
      [page]="page()"
      [hasNext]="hasNext()"
      [hasPrevious]="hasPrevious()"
      (pageChange)="onPageChange($event)"
    />
  `,
})
class TestHostComponent {
  total = signal(100);
  limit = signal(20);
  page = signal(1);
  hasNext = signal(true);
  hasPrevious = signal(false);
  lastEvent: PageChangeEvent | null = null;

  onPageChange(event: PageChangeEvent): void {
    this.lastEvent = event;
  }
}

describe('PaginationComponent', () => {
  let fixture: ComponentFixture<TestHostComponent>;
  let host: TestHostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TestHostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(TestHostComponent);
    host = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should display correct page info', () => {
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Showing');
    expect(el.textContent).toContain('1');
    expect(el.textContent).toContain('20');
    expect(el.textContent).toContain('100');
    expect(el.textContent).toContain('Page 1 of 5');
  });

  it('should disable Previous button on first page', () => {
    const prevButton = fixture.nativeElement.querySelector('button:first-of-type') as HTMLButtonElement;
    expect(prevButton.disabled).toBe(true);
  });

  it('should enable Next button when hasNext is true', () => {
    const nextButton = fixture.nativeElement.querySelector('button:last-of-type') as HTMLButtonElement;
    expect(nextButton.disabled).toBe(false);
  });

  it('should emit pageChange with direction next on Next click', () => {
    const nextButton = fixture.nativeElement.querySelector('button:last-of-type') as HTMLButtonElement;
    nextButton.click();
    expect(host.lastEvent).toEqual({ direction: 'next' });
  });

  it('should emit pageChange with direction previous on Previous click', () => {
    host.page.set(3);
    host.hasPrevious.set(true);
    fixture.detectChanges();

    const prevButton = fixture.nativeElement.querySelector('button:first-of-type') as HTMLButtonElement;
    prevButton.click();
    expect(host.lastEvent).toEqual({ direction: 'previous' });
  });

  it('should disable Next button when hasNext is false', () => {
    host.hasNext.set(false);
    fixture.detectChanges();

    const nextButton = fixture.nativeElement.querySelector('button:last-of-type') as HTMLButtonElement;
    expect(nextButton.disabled).toBe(true);
  });

  it('should show correct info for zero results', () => {
    host.total.set(0);
    host.hasNext.set(false);
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('0');
    expect(el.textContent).toContain('Page 1 of 1');
  });

  it('should show correct info for partial last page', () => {
    host.total.set(45);
    host.page.set(3);
    host.hasNext.set(false);
    host.hasPrevious.set(true);
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('41');
    expect(el.textContent).toContain('45');
    expect(el.textContent).toContain('Page 3 of 3');
  });
});
