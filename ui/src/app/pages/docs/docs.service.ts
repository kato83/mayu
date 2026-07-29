import { HttpClient } from '@angular/common/http';
import { Injectable, inject, LOCALE_ID } from '@angular/core';
import { catchError, type Observable, of } from 'rxjs';

import { DOCS_MANIFEST, type DocEntry } from './docs-manifest';

@Injectable({
  providedIn: 'root',
})
export class DocsService {
  private readonly http = inject(HttpClient);
  private readonly locale = inject(LOCALE_ID);

  getDocument(slug: string): Observable<string> {
    const entry = DOCS_MANIFEST.find((d) => d.slug === slug);
    if (!entry) {
      return of('');
    }

    if (this.locale === 'ja' && entry.filenameJa) {
      return this.http
        .get(entry.filenameJa, { responseType: 'text' })
        .pipe(catchError(() => this.http.get(entry.filename, { responseType: 'text' })));
    }

    return this.http.get(entry.filename, { responseType: 'text' });
  }

  getEntry(slug: string): DocEntry | undefined {
    return DOCS_MANIFEST.find((d) => d.slug === slug);
  }
}
