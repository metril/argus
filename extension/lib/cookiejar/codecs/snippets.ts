import { hostOfCookie, matchesUrl, type Cookie } from '../model';
import type { SnippetId } from './types';

/** Single-quotes a shell word. */
export const shq = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

const SAFE_HEADER = /^[^\r\n\x00]*$/;

export interface SnippetOptions {
  /** The URL the command fetches; cookies a request to it would not send are left out. */
  url?: string;
}

export const SNIPPETS: { id: SnippetId; label: string }[] = [
  { id: 'curl', label: 'curl' },
  { id: 'wget', label: 'wget' },
  { id: 'ytdlp', label: 'yt-dlp' },
];

/** A command that fetches `url` with these cookies; '' when none of them would be sent. */
export function snippet(id: SnippetId, cookies: Cookie[], o: SnippetOptions = {}): string {
  const first = cookies[0];
  if (!first) return '';
  const url = o.url ?? `https://${hostOfCookie(first)}/`;
  const sent = cookies.filter((c) => matchesUrl(c, url) && SAFE_HEADER.test(c.name + c.value));
  if (sent.length === 0) return '';
  const hdr = sent.map((c) => `${c.name}=${c.value}`).join('; ');
  switch (id) {
    case 'curl': return `curl -b ${shq(hdr)} ${shq(url)}`;
    case 'wget': return `wget --header ${shq('Cookie: ' + hdr)} ${shq(url)}`;
    case 'ytdlp': return `yt-dlp --add-headers ${shq('Cookie: ' + hdr)} ${shq(url)}`;
  }
}
