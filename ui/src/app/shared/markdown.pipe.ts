import { Pipe, PipeTransform } from '@angular/core';
import { Marked, Tokens } from 'marked';
import DOMPurify from 'dompurify';

/**
 * Converts Markdown text to sanitized HTML.
 *
 * Uses `marked` for Markdown→HTML conversion and `DOMPurify` for XSS protection.
 * Links are rendered with `target="_blank"` and `rel="noopener noreferrer"`.
 *
 * @example
 * <div [innerHTML]="details | markdown"></div>
 */
@Pipe({
  name: 'markdown',
  standalone: true,
})
export class MarkdownPipe implements PipeTransform {
  private readonly markedInstance: Marked;

  constructor() {
    this.markedInstance = new Marked({
      breaks: true,
      renderer: {
        link({ href, title, tokens }: Tokens.Link): string {
          const text = this.parser.parseInline(tokens);
          const titleAttr = title ? ` title="${title}"` : '';
          return `<a href="${href}"${titleAttr} target="_blank" rel="noopener noreferrer">${text}</a>`;
        },
      },
    });
  }

  transform(value: string | null | undefined): string {
    if (!value) {
      return '';
    }

    const html = this.markedInstance.parse(value) as string;

    return this.sanitize(html);
  }

  private sanitize(html: string): string {
    // DOMPurify default export is an instance in browser (with window),
    // but a factory function in Node.js environments (no window).
    const purify = typeof DOMPurify === 'function' && !('sanitize' in DOMPurify)
      ? (DOMPurify as unknown as (root?: unknown) => { sanitize: (html: string, config?: object) => string })(globalThis.window ?? globalThis)
      : DOMPurify as unknown as { sanitize: (html: string, config?: object) => string };

    return purify.sanitize(html, {
      ADD_ATTR: ['target', 'rel'],
    });
  }
}
