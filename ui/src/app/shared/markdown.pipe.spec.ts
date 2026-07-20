// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { MarkdownPipe } from './markdown.pipe';

describe('MarkdownPipe', () => {
  let pipe: MarkdownPipe;

  beforeEach(() => {
    pipe = new MarkdownPipe();
  });

  it('should create an instance', () => {
    expect(pipe).toBeTruthy();
  });

  it('should return empty string for null or undefined', () => {
    expect(pipe.transform(null)).toBe('');
    expect(pipe.transform(undefined)).toBe('');
  });

  it('should return empty string for empty string input', () => {
    expect(pipe.transform('')).toBe('');
  });

  it('should render bold text', () => {
    const result = pipe.transform('**bold**');
    expect(result).toContain('<strong>bold</strong>');
  });

  it('should render italic text', () => {
    const result = pipe.transform('*italic*');
    expect(result).toContain('<em>italic</em>');
  });

  it('should render inline code', () => {
    const result = pipe.transform('`code`');
    expect(result).toContain('<code>code</code>');
  });

  it('should render code blocks', () => {
    const result = pipe.transform('```\nconst x = 1;\n```');
    expect(result).toContain('<code>');
    expect(result).toContain('const x = 1;');
  });

  it('should render links with target="_blank" and rel="noopener noreferrer"', () => {
    const result = pipe.transform('[example](https://example.com)');
    expect(result).toContain('href="https://example.com"');
    expect(result).toContain('target="_blank"');
    expect(result).toContain('rel="noopener noreferrer"');
  });

  it('should render headers', () => {
    const result = pipe.transform('## Heading');
    expect(result).toContain('<h2');
    expect(result).toContain('Heading');
  });

  it('should render unordered lists', () => {
    const result = pipe.transform('- item 1\n- item 2');
    expect(result).toContain('<li>');
    expect(result).toContain('item 1');
    expect(result).toContain('item 2');
  });

  it('should sanitize script tags (XSS prevention)', () => {
    const result = pipe.transform('<script>alert("xss")</script>');
    expect(result).not.toContain('<script>');
    expect(result).not.toContain('alert');
  });

  it('should sanitize event handlers (XSS prevention)', () => {
    const result = pipe.transform('<img src=x onerror="alert(1)">');
    expect(result).not.toContain('onerror');
  });

  it('should sanitize javascript: URIs in links', () => {
    const result = pipe.transform('[click](javascript:alert(1))');
    expect(result).not.toContain('javascript:');
  });

  it('should render paragraphs', () => {
    const result = pipe.transform('Hello world');
    expect(result).toContain('<p>Hello world</p>');
  });

  it('should handle line breaks with breaks option', () => {
    const result = pipe.transform('line 1\nline 2');
    expect(result).toContain('<br');
  });
});
