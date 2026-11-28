import type { Cookie } from '../model';

export type FormatId = 'netscape' | 'json' | 'header' | 'csv' | 'playwright' | 'puppeteer';
export type SnippetId = 'curl' | 'wget' | 'ytdlp';

export interface ParseContext {
  /** The site the pasted text belongs to; formats without a domain (a Cookie header) need it. */
  host?: string;
  /** Milliseconds since the epoch (Max-Age in a Set-Cookie line, tests). */
  now?: number;
}

/** One row of pasted text: a cookie, or the reason it could not be read. */
export interface ParsedRow {
  /** 1-based line, or index for structured formats. */
  row: number;
  cookie?: Cookie;
  error?: string;
}

export interface Codec {
  id: FormatId;
  label: string;
  extension: string;
  mime: string;
  export(cookies: Cookie[]): string;
  parse(text: string, ctx?: ParseContext): ParsedRow[];
}

export const stripBom = (s: string): string => s.replace(/^﻿/, '');
