import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ConfirmDialogComponent } from './confirm-dialog.component';

describe('ConfirmDialogComponent', () => {
  let component: ConfirmDialogComponent;
  let fixture: ComponentFixture<ConfirmDialogComponent>;
  let dialogEl: HTMLDialogElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfirmDialogComponent],
    }).compileComponents();
    fixture = TestBed.createComponent(ConfirmDialogComponent);
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

  it('should set title and message when opened', async () => {
    const promise = component.open({
      title: 'Delete Item',
      message: 'Are you sure?',
    });
    fixture.detectChanges();
    expect(component.title()).toBe('Delete Item');
    expect(component.message()).toBe('Are you sure?');
    expect(dialogEl.showModal).toHaveBeenCalled();

    component.cancel();
    await promise;
  });

  it('should use default labels when not provided', async () => {
    const promise = component.open({
      title: 'Confirm',
      message: 'Proceed?',
    });
    fixture.detectChanges();
    expect(component.confirmLabel()).toBe('OK');
    expect(component.cancelLabel()).toBe('Cancel');

    component.cancel();
    await promise;
  });

  it('should use custom labels when provided', async () => {
    const promise = component.open({
      title: 'Remove',
      message: 'Remove this?',
      confirmLabel: 'Remove',
      cancelLabel: 'Keep',
    });
    fixture.detectChanges();
    expect(component.confirmLabel()).toBe('Remove');
    expect(component.cancelLabel()).toBe('Keep');

    component.cancel();
    await promise;
  });

  it('should resolve true on confirm', async () => {
    const promise = component.open({
      title: 'Test',
      message: 'Test message',
    });
    component.confirm();
    const result = await promise;
    expect(result).toBe(true);
  });

  it('should resolve false on cancel', async () => {
    const promise = component.open({
      title: 'Test',
      message: 'Test message',
    });
    component.cancel();
    const result = await promise;
    expect(result).toBe(false);
  });

  it('should resolve false on dialog close (Escape)', async () => {
    const promise = component.open({
      title: 'Test',
      message: 'Test message',
    });
    component.onClose();
    const result = await promise;
    expect(result).toBe(false);
  });

  it('should set destructive flag', async () => {
    const promise = component.open({
      title: 'Delete',
      message: 'This is destructive',
      destructive: true,
    });
    fixture.detectChanges();
    expect(component.destructive()).toBe(true);

    component.cancel();
    await promise;
  });

  it('should default destructive to false', async () => {
    const promise = component.open({
      title: 'Normal',
      message: 'Non-destructive',
    });
    fixture.detectChanges();
    expect(component.destructive()).toBe(false);

    component.cancel();
    await promise;
  });
});
