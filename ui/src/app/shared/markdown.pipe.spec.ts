// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { MarkdownPipe } from './markdown.pipe';

describe('MarkdownPipe', () => {
  let pipe: MarkdownPipe;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [MarkdownPipe],
    });
    pipe = TestBed.inject(MarkdownPipe);
  });

  it('should create an instance', () => {
    expect(pipe).toBeTruthy();
  });

  it('should return empty string for null or undefined', () => {
    expect(pipe.toHtml(null)).toBe('');
    expect(pipe.toHtml(undefined)).toBe('');
  });

  it('should return empty string for empty string input', () => {
    expect(pipe.toHtml('')).toBe('');
  });

  it('should render bold text', () => {
    const result = pipe.toHtml('**bold**');
    expect(result).toContain('<strong>bold</strong>');
  });

  it('should render italic text', () => {
    const result = pipe.toHtml('*italic*');
    expect(result).toContain('<em>italic</em>');
  });

  it('should render inline code', () => {
    const result = pipe.toHtml('`code`');
    expect(result).toContain('<code>code</code>');
  });

  it('should render code blocks', () => {
    const result = pipe.toHtml('```\nconst x = 1;\n```');
    expect(result).toContain('<code>');
    expect(result).toContain('const x = 1;');
  });

  it('should render links with target="_blank" and rel="noopener noreferrer"', () => {
    const result = pipe.toHtml('[example](https://example.com)');
    expect(result).toContain('href="https://example.com"');
    expect(result).toContain('target="_blank"');
    expect(result).toContain('rel="noopener noreferrer"');
  });

  it('should render headers', () => {
    const result = pipe.toHtml('## Heading');
    expect(result).toContain('<h2');
    expect(result).toContain('Heading');
  });

  it('should render headers with id attribute', () => {
    const result = pipe.toHtml('## Hello World');
    expect(result).toContain('id="hello-world"');
  });

  it('should slugify heading text for id', () => {
    const result = pipe.toHtml('### Hello World');
    expect(result).toContain('id="hello-world"');
    expect(result).toContain('<h3');
  });

  it('should add badge class to shields.io images', () => {
    const result = pipe.toHtml('![CI](https://img.shields.io/badge/test-passing-green)');
    expect(result).toContain('class="badge"');
  });

  it('should add badge class to github actions badge.svg images', () => {
    const result = pipe.toHtml('![CI](https://github.com/owner/repo/actions/workflows/ci.yml/badge.svg)');
    expect(result).toContain('class="badge"');
  });

  it('should not add badge class to regular images', () => {
    const result = pipe.toHtml('![photo](https://example.com/photo.png)');
    expect(result).not.toContain('class="badge"');
  });

  it('should render unordered lists', () => {
    const result = pipe.toHtml('- item 1\n- item 2');
    expect(result).toContain('<li>');
    expect(result).toContain('item 1');
    expect(result).toContain('item 2');
  });

  it('should sanitize script tags (XSS prevention)', () => {
    const result = pipe.toHtml('<script>alert("xss")</script>');
    expect(result).not.toContain('<script>');
    expect(result).not.toContain('alert');
  });

  it('should sanitize event handlers (XSS prevention)', () => {
    const result = pipe.toHtml('<img src=x onerror="alert(1)">');
    expect(result).not.toContain('onerror');
  });

  it('should sanitize javascript: URIs in links', () => {
    const result = pipe.toHtml('[click](javascript:alert(1))');
    expect(result).not.toContain('javascript:');
  });

  it('should render paragraphs', () => {
    const result = pipe.toHtml('Hello world');
    expect(result).toContain('<p>Hello world</p>');
  });

  it('should handle line breaks with breaks option', () => {
    const result = pipe.toHtml('line 1\nline 2');
    expect(result).toContain('<br');
  });

  it('should return SafeHtml from transform()', () => {
    const result = pipe.transform('**bold**');
    // SafeHtml is an object with changingThisBreaksApplicationSecurity property
    expect(result).toBeTruthy();
    expect(typeof result).not.toBe('string');
  });

  it('should wrap tables in a scrollable container', () => {
    const result = pipe.toHtml('| A | B |\n|---|---|\n| 1 | 2 |');
    expect(result).toContain('<div class="overflow-x-auto"><table>');
    expect(result).toContain('</table></div>');
  });

  it('should generate slugs for Japanese headings', () => {
    const result = pipe.toHtml('## 概要');
    expect(result).toContain('id="概要"');
  });

  it('should generate slugs for mixed-language headings', () => {
    const result = pipe.toHtml('## Quick Start ガイド');
    expect(result).toContain('id="quick-start-ガイド"');
  });
});
