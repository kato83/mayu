import { Component, signal } from '@angular/core';
import { type ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';

import { CvssVectorComponent } from './cvss-vector.component';

@Component({
  standalone: true,
  imports: [CvssVectorComponent],
  template: `<app-cvss-vector [vector]="vector()" />`,
})
class TestHostComponent {
  vector = signal('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
}

describe('CvssVectorComponent', () => {
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

  describe('version detection', () => {
    it('should detect CVSS v3.1', () => {
      host.vector.set('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const code = el.querySelector('code');
      expect(code?.textContent).toContain('CVSS:3.1');
    });

    it('should detect CVSS v3.0', () => {
      host.vector.set('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const code = el.querySelector('code');
      expect(code?.textContent).toContain('CVSS:3.0');
    });

    it('should detect CVSS v4.0', () => {
      host.vector.set('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const code = el.querySelector('code');
      expect(code?.textContent).toContain('CVSS:4.0');
    });

    it('should detect CVSS v2.0 (no prefix)', () => {
      host.vector.set('AV:N/AC:L/Au:N/C:C/I:C/A:C');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const code = el.querySelector('code');
      expect(code?.textContent).toBe('AV:N/AC:L/Au:N/C:C/I:C/A:C');
      // Should still show the toggle button (metrics are parseable)
      const button = el.querySelector('button');
      expect(button).toBeTruthy();
    });
  });

  describe('metric parsing', () => {
    it('should parse v3.1 metrics correctly', () => {
      host.vector.set('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      fixture.detectChanges();

      // Expand to see the table
      const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
      button.click();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const rows = el.querySelectorAll('tbody tr');
      expect(rows.length).toBe(8); // AV, AC, PR, UI, S, C, I, A
    });

    it('should parse v2.0 metrics correctly', () => {
      host.vector.set('AV:N/AC:L/Au:N/C:C/I:C/A:C');
      fixture.detectChanges();

      const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
      button.click();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const rows = el.querySelectorAll('tbody tr');
      expect(rows.length).toBe(6); // AV, AC, Au, C, I, A
    });

    it('should parse v4.0 metrics correctly', () => {
      host.vector.set('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
      fixture.detectChanges();

      const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
      button.click();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const rows = el.querySelectorAll('tbody tr');
      expect(rows.length).toBe(11); // AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA
    });

    it('should display metric names and values', () => {
      host.vector.set('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      fixture.detectChanges();

      const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
      button.click();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const tableText = el.querySelector('table')?.textContent ?? '';
      expect(tableText).toContain('Attack Vector');
      expect(tableText).toContain('Network');
      expect(tableText).toContain('Attack Complexity');
      expect(tableText).toContain('Low');
    });
  });

  describe('component rendering', () => {
    it('should display the raw vector as code', () => {
      const el = fixture.nativeElement as HTMLElement;
      const code = el.querySelector('code');
      expect(code).toBeTruthy();
      expect(code?.textContent).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(code?.classList.contains('text-xs')).toBe(true);
    });

    it('should show toggle button', () => {
      const el = fixture.nativeElement as HTMLElement;
      const button = el.querySelector('button');
      expect(button).toBeTruthy();
      expect(button?.textContent?.trim()).toBe('▼');
    });

    it('should not show table when collapsed', () => {
      const el = fixture.nativeElement as HTMLElement;
      const table = el.querySelector('table');
      expect(table).toBeNull();
    });
  });

  describe('toggle expand/collapse', () => {
    it('should expand on click', () => {
      const el = fixture.nativeElement as HTMLElement;
      const button = el.querySelector('button') as HTMLButtonElement;

      button.click();
      fixture.detectChanges();

      const table = el.querySelector('table');
      expect(table).toBeTruthy();
      expect(button.textContent?.trim()).toBe('▲');
    });

    it('should collapse on second click', () => {
      const el = fixture.nativeElement as HTMLElement;
      const button = el.querySelector('button') as HTMLButtonElement;

      // Expand
      button.click();
      fixture.detectChanges();
      expect(el.querySelector('table')).toBeTruthy();

      // Collapse
      button.click();
      fixture.detectChanges();
      expect(el.querySelector('table')).toBeNull();
    });

    it('should set aria-expanded attribute', () => {
      const el = fixture.nativeElement as HTMLElement;
      const button = el.querySelector('button') as HTMLButtonElement;

      expect(button.getAttribute('aria-expanded')).toBe('false');

      button.click();
      fixture.detectChanges();
      expect(button.getAttribute('aria-expanded')).toBe('true');
    });
  });

  describe('unknown metrics handling', () => {
    it('should handle unknown metrics gracefully', () => {
      host.vector.set('CVSS:3.1/AV:N/XX:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      fixture.detectChanges();

      const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
      button.click();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const rows = el.querySelectorAll('tbody tr');
      // Should still render all metrics including the unknown one
      expect(rows.length).toBe(9);
      const tableText = el.querySelector('table')?.textContent ?? '';
      expect(tableText).toContain('XX');
    });

    it('should handle unknown metric values gracefully', () => {
      host.vector.set('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      fixture.detectChanges();

      const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
      button.click();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const rows = el.querySelectorAll('tbody tr');
      expect(rows.length).toBe(8);
      // Should still show the metric key even with unknown value
      const tableText = el.querySelector('table')?.textContent ?? '';
      expect(tableText).toContain('AV');
      expect(tableText).toContain('Attack Vector');
    });

    it('should handle empty vector string without errors', () => {
      host.vector.set('');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const button = el.querySelector('button');
      // No toggle button when metrics can't be parsed
      expect(button).toBeNull();
    });

    it('should handle malformed vector string without errors', () => {
      host.vector.set('not-a-valid-vector');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      const code = el.querySelector('code');
      expect(code?.textContent).toBe('not-a-valid-vector');
      const button = el.querySelector('button');
      expect(button).toBeNull();
    });
  });
});
