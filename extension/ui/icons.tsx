const P = {
  eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12zM9 12a3 3 0 106 0 3 3 0 00-6 0',
  dots: 'M4 12h.01M12 12h.01M20 12h.01',
  shield: 'M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zM8.5 12l2.5 2.5 4.5-5',
  shieldX: 'M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zM9 9l6 6M15 9l-6 6',
  lock: 'M5 11h14v9H5zM8 11V8a4 4 0 018 0v3',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  play: 'M7 5l12 7-12 7z',
  key: 'M4 15a4 4 0 108 0 4 4 0 00-8 0M11 12l9-9M17 6l3 3',
  user: 'M8 8a4 4 0 108 0 4 4 0 00-8 0M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6',
  out: 'M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9',
  globe: 'M3 12a9 9 0 1018 0 9 9 0 00-18 0M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18',
  warn: 'M12 3l10 18H2zM12 10v5M12 18v.5',
  ban: 'M3 12a9 9 0 1018 0 9 9 0 00-18 0M5.6 5.6l12.8 12.8',
  plug: 'M9 7V3M15 7V3M7 7h10v4a5 5 0 01-10 0zM12 16v5',
  copy: 'M9 9h11v11H9zM5 15V5h10',
  check: 'M5 12l5 5 9-10',
  x: 'M6 6l12 12M18 6L6 18',
  info: 'M3 12a9 9 0 1018 0 9 9 0 00-18 0M12 11v5M12 8v.5',
  cookie: 'M12 3a9 9 0 109 9 4 4 0 01-4-4 4 4 0 01-5-5zM8.5 10h.01M12 15h.01M15.5 13.5h.01M9 15.5h.01',
  back: 'M19 12H5M11 6l-6 6 6 6',
} as const;

export type IconName = keyof typeof P;

export function Icon({ n, size = 14, sw = 2 }: { n: IconName; size?: number; sw?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width={sw} stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d={P[n]} />
    </svg>
  );
}
