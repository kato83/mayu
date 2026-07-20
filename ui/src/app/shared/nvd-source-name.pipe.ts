import { Pipe, PipeTransform } from '@angular/core';

/**
 * Maps NVD metric source identifiers (UUIDs or emails) to human-readable names.
 *
 * NVD API uses UUIDs as organization identifiers for metric sources.
 * This pipe resolves well-known UUIDs to display names while passing
 * through already-readable values (like email addresses) unchanged.
 *
 * @example
 * {{ metric.source | nvdSourceName }}
 * // "134c704f-9b21-4f2e-91b3-4a467353bcc0" → "CISA-ADP"
 * // "nvd@nist.gov" → "nvd@nist.gov"
 */
@Pipe({
  name: 'nvdSourceName',
  standalone: true,
})
export class NvdSourceNamePipe implements PipeTransform {
  /**
   * Well-known NVD source UUIDs mapped to human-readable names.
   * Source: NVD Source API (https://nvd.nist.gov/developers/data-sources)
   * and CISA Vulnrichment (https://github.com/cisagov/vulnrichment)
   */
  private static readonly SOURCE_MAP: Record<string, string> = {
    '134c704f-9b21-4f2e-91b3-4a467353bcc0': 'CISA-ADP',
    'af854a3a-2127-422b-91ae-364da2661108': 'NVD-CNA',
  };

  private static readonly UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  transform(value: string | null | undefined): string {
    if (!value) {
      return '';
    }

    const mapped = NvdSourceNamePipe.SOURCE_MAP[value.toLowerCase()];
    if (mapped) {
      return mapped;
    }

    // If it's an unmapped UUID, show a truncated form for readability
    if (NvdSourceNamePipe.UUID_PATTERN.test(value)) {
      return value.substring(0, 8) + '…';
    }

    return value;
  }
}
