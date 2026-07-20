import { describe, it, expect, beforeEach } from 'vitest';
import { NvdSourceNamePipe } from './nvd-source-name.pipe';

describe('NvdSourceNamePipe', () => {
  let pipe: NvdSourceNamePipe;

  beforeEach(() => {
    pipe = new NvdSourceNamePipe();
  });

  it('should create an instance', () => {
    expect(pipe).toBeTruthy();
  });

  it('should map CISA-ADP UUID to "CISA-ADP"', () => {
    expect(pipe.transform('134c704f-9b21-4f2e-91b3-4a467353bcc0')).toBe('CISA-ADP');
  });

  it('should map CISA-ADP UUID case-insensitively', () => {
    expect(pipe.transform('134C704F-9B21-4F2E-91B3-4A467353BCC0')).toBe('CISA-ADP');
  });

  it('should map NVD-CNA UUID to "NVD-CNA"', () => {
    expect(pipe.transform('af854a3a-2127-422b-91ae-364da2661108')).toBe('NVD-CNA');
  });

  it('should pass through email addresses unchanged', () => {
    expect(pipe.transform('nvd@nist.gov')).toBe('nvd@nist.gov');
    expect(pipe.transform('contact@wpscan.com')).toBe('contact@wpscan.com');
    expect(pipe.transform('cve@mitre.org')).toBe('cve@mitre.org');
  });

  it('should truncate unknown UUIDs', () => {
    const unknownUuid = 'abcdef01-2345-6789-abcd-ef0123456789';
    expect(pipe.transform(unknownUuid)).toBe('abcdef01…');
  });

  it('should return empty string for null or undefined', () => {
    expect(pipe.transform(null)).toBe('');
    expect(pipe.transform(undefined)).toBe('');
  });

  it('should return empty string for empty string input', () => {
    expect(pipe.transform('')).toBe('');
  });
});
