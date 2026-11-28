import { csv } from './csv';
import { header } from './header';
import { json } from './json';
import { netscape } from './netscape';
import { playwright } from './playwright';
import { puppeteer } from './puppeteer';
import type { Codec, FormatId } from './types';

export type { Codec, FormatId, ParseContext, ParsedRow, SnippetId } from './types';
export { snippet, SNIPPETS, shq } from './snippets';

export const CODECS: Record<FormatId, Codec> = { netscape, json, header, csv, playwright, puppeteer };
export const FORMAT_IDS = Object.keys(CODECS) as FormatId[];
