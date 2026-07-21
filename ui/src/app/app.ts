import { Component, HostListener, viewChild, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';

import { ExternalLinkDialogComponent } from './shared/external-link-dialog/external-link-dialog.component';
import { ThemeService } from './services/theme.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, ExternalLinkDialogComponent],
  template: `
    <router-outlet />
    <app-external-link-dialog />
  `,
})
export class App {
  // Ensure ThemeService is initialized at app startup
  private readonly _theme = inject(ThemeService);
  private readonly dialog = viewChild.required(ExternalLinkDialogComponent);

  @HostListener('document:click', ['$event'])
  async onDocumentClick(event: MouseEvent): Promise<void> {
    const anchor = this.findAnchor(event.target as HTMLElement);
    if (!anchor) return;

    const href = anchor.getAttribute('href');
    if (!href) return;

    // Skip internal links (routerLink, relative paths, same origin)
    if (!this.isExternalUrl(href)) return;

    // Ensure external links open in new tab
    anchor.setAttribute('target', '_blank');
    anchor.setAttribute('rel', 'noopener noreferrer');

    // Prevent default navigation and show cushion dialog
    event.preventDefault();
    event.stopPropagation();

    const proceed = await this.dialog().open(href);
    if (proceed) {
      window.open(href, '_blank', 'noopener,noreferrer');
    }
  }

  private findAnchor(el: HTMLElement | null): HTMLAnchorElement | null {
    while (el) {
      if (el.tagName === 'A') {
        return el as HTMLAnchorElement;
      }
      el = el.parentElement;
    }
    return null;
  }

  private isExternalUrl(href: string): boolean {
    // Skip fragment-only links, relative paths, javascript:, mailto:, tel:
    if (
      href.startsWith('#') ||
      href.startsWith('/') ||
      href.startsWith('javascript:') ||
      href.startsWith('mailto:') ||
      href.startsWith('tel:')
    ) {
      return false;
    }

    try {
      const url = new URL(href, window.location.origin);
      return url.origin !== window.location.origin;
    } catch {
      return false;
    }
  }
}
