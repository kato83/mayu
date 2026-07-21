import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ExternalLinkDialogComponent } from './external-link-dialog.component';

describe('ExternalLinkDialogComponent', () => {
  let component: ExternalLinkDialogComponent;
  let fixture: ComponentFixture<ExternalLinkDialogComponent>;
  let dialogEl: HTMLDialogElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ExternalLinkDialogComponent],
    }).compileComponents();
    fixture = TestBed.createComponent(ExternalLinkDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    dialogEl = fixture.nativeElement.querySelector('dialog');
    // Mock showModal/close since test environments don't support them
    dialogEl.showModal = vi.fn();
    dialogEl.close = vi.fn();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should have a dialog element', () => {
    expect(dialogEl).toBeTruthy();
  });

  it('should set url when opened', async () => {
    const promise = component.open('https://example.com');
    fixture.detectChanges();
    expect(component.url()).toBe('https://example.com');
    expect(dialogEl.showModal).toHaveBeenCalled();

    component.cancel();
    const result = await promise;
    expect(result).toBe(false);
  });

  it('should resolve true on proceed', async () => {
    const promise = component.open('https://example.com');
    component.proceed();
    const result = await promise;
    expect(result).toBe(true);
  });

  it('should resolve false on cancel', async () => {
    const promise = component.open('https://example.com');
    component.cancel();
    const result = await promise;
    expect(result).toBe(false);
  });

  it('should resolve false on dialog close (Escape)', async () => {
    const promise = component.open('https://example.com');
    component.onClose();
    const result = await promise;
    expect(result).toBe(false);
  });

  it('should display the URL in the dialog', async () => {
    const promise = component.open('https://github.com/example');
    fixture.detectChanges();

    const urlEl = fixture.nativeElement.querySelector('.font-mono');
    expect(urlEl?.textContent?.trim()).toBe('https://github.com/example');

    component.cancel();
    await promise;
  });
});
