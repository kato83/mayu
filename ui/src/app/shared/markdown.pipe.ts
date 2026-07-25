import { Pipe, PipeTransform } from '@angular/core';
import { Marked, Tokens } from 'marked';
import DOMPurify from 'dompurify';

/**
 * Converts Markdown text to sanitized HTML.
 *
 * Uses `marked` for Markdown→HTML conversion and `DOMPurify` for XSS protection.
 * Links are rendered with `target="_blank"` and `rel="noopener noreferrer"`.
 * Headings are rendered with slugified `id` attributes for anchor navigation.
 * Badge images (shields.io, github actions) are rendered with a `badge` class.
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
        heading({ text, depth }: Tokens.Heading): string {
          // Strip HTML tags from text for slug generation
          const plainText = text.replace(/<[^>]*>/g, '');
          const slug = plainText
            .toLowerCase()
            .replace(/[^\w\s-]/g, '')
            .replace(/\s+/g, '-');
          return `<h${depth} id="${slug}">${text}</h${depth}>\n`;
        },
        image({ href, title, text }: Tokens.Image): string {
          const isBadge =
            href.includes('shields.io') ||
            href.includes('badge.svg') ||
            href.includes('img.shields.io');
          const badgeClass = isBadge ? ' class="badge"' : '';
          const titleAttr = title ? ` title="${title}"` : '';
          return `<img src="${href}" alt="${text}"${titleAttr}${badgeClass}>`;
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
      ADD_ATTR: ['target', 'rel', 'id'],
    });
  }
}
