import { signal } from '@preact/signals';
import type { ComponentChildren } from 'preact';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { Icon } from '../icons';

export type PillKind = 'ok' | 'warn' | 'err' | 'info' | 'acc' | '';

export function Pill({ kind = '', mono, title, children }: { kind?: PillKind; mono?: boolean; title?: string; children: ComponentChildren }) {
  return <span class={`pill ${kind}${mono ? ' mono' : ''}`} {...(title ? { title } : {})}>{children}</span>;
}

/** A text-with-icon info line: `Icon` then text. */
export function Hint({ children }: { children: ComponentChildren }) {
  return <div class="hint hint-i"><Icon n="info" size={14} /><span>{children}</span></div>;
}

// -- segmented control (radiogroup) --------------------------------------------------------------
export interface SegOption<T extends string> { v: T; l: string; n?: number | string }

export function Segmented<T extends string>({ label, options, value, onChange, cls = '', id }: {
  label: string; options: SegOption<T>[]; value: T; onChange: (v: T) => void; cls?: string; id?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const move = (e: KeyboardEvent, i: number) => {
    let to = i;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') to = (i + 1) % options.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') to = (i - 1 + options.length) % options.length;
    else if (e.key === 'Home') to = 0;
    else if (e.key === 'End') to = options.length - 1;
    else return;
    e.preventDefault();
    onChange(options[to]!.v);
    requestAnimationFrame(() => (ref.current?.querySelectorAll<HTMLElement>('[role=radio]')[to])?.focus());
  };
  return (
    <div ref={ref} class={`seg ${cls}`} role="radiogroup" aria-label={label} {...(id ? { id } : {})}>
      {options.map((o, i) => {
        const on = o.v === value;
        return (
          <button key={o.v} type="button" role="radio" aria-checked={on} tabIndex={on ? 0 : -1} onClick={() => onChange(o.v)} onKeyDown={(e) => move(e, i)}>
            {o.l}{o.n !== undefined && <span class="n">{o.n}</span>}
          </button>
        );
      })}
    </div>
  );
}

// -- tabs ------------------------------------------------------------------------------------------
export function Tabs<T extends string>({ label, tabs, value, onChange, idPrefix }: {
  label: string; tabs: { v: T; l: string }[]; value: T; onChange: (v: T) => void; idPrefix: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const key = (e: KeyboardEvent, i: number) => {
    let to = i;
    if (e.key === 'ArrowRight') to = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') to = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') to = 0;
    else if (e.key === 'End') to = tabs.length - 1;
    else return;
    e.preventDefault();
    onChange(tabs[to]!.v);
    requestAnimationFrame(() => (ref.current?.querySelectorAll<HTMLElement>('[role=tab]')[to])?.focus());
  };
  return (
    <div ref={ref} class="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button key={t.v} type="button" role="tab" id={`${idPrefix}-tab-${t.v}`} aria-selected={t.v === value} aria-controls={`${idPrefix}-panel`} tabIndex={t.v === value ? 0 : -1} onClick={() => onChange(t.v)} onKeyDown={(e) => key(e, i)}>{t.l}</button>
      ))}
    </div>
  );
}

// -- tick box and switch ----------------------------------------------------------------------------
export function Tick({ checked, label, onChange, disabled, id }: { checked: boolean | 'mixed'; label: string; onChange: (v: boolean) => void; disabled?: boolean; id?: string }) {
  return <button type="button" class="cbx" role="checkbox" aria-checked={checked} aria-label={label} disabled={disabled} {...(id ? { id } : {})} onClick={(e) => { e.stopPropagation(); onChange(checked !== true); }} />;
}

export function Sw({ on, label, onChange, disabled, id }: { on: boolean; label: string; onChange: (v: boolean) => void; disabled?: boolean; id?: string }) {
  return <button type="button" class="sw" role="switch" aria-checked={on} aria-label={label} disabled={disabled} {...(id ? { id } : {})} onClick={() => onChange(!on)} />;
}

/** A switch with its visible label beside it. */
export function SwRow({ on, label, onChange, disabled, id }: { on: boolean; label: string; onChange: (v: boolean) => void; disabled?: boolean; id?: string }) {
  return (
    <div class="chk">
      <Sw on={on} label={label} onChange={onChange} {...(disabled ? { disabled } : {})} {...(id ? { id } : {})} />
      <span onClick={() => { if (!disabled) onChange(!on); }}>{label}</span>
    </div>
  );
}

// -- confirm button --------------------------------------------------------------------------------
/** The same button in the same spot turns into "<label>?" with a Cancel beside it; it reverts after 4 s, on blur and on Esc. */
export function Confirm({ label, onConfirm, onArm, onDisarm, neutral, sm, left, aria, disabled, testid }: {
  label: string; onConfirm: () => void; onArm?: () => void; onDisarm?: () => void; neutral?: boolean; sm?: boolean; left?: boolean; aria?: string; disabled?: boolean; testid?: string;
}) {
  const [armed, setArmed] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  const wrap = useRef<HTMLSpanElement>(null);
  const main = useRef<HTMLButtonElement>(null);
  const off = () => { clearTimeout(timer.current); setArmed((a) => { if (a) onDisarm?.(); return false; }); };
  useEffect(() => () => clearTimeout(timer.current), []);
  const arm = () => { setArmed(true); onArm?.(); clearTimeout(timer.current); timer.current = setTimeout(off, 4000); };
  return (
    <span
      ref={wrap}
      class={`cfm${left ? ' l' : ''}${armed ? ' armed' : ''}`}
      onKeyDown={(e) => { if (armed && e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); off(); main.current?.focus(); } }}
      onFocusOut={(e) => { const n = (e as FocusEvent).relatedTarget as Node | null; if (armed && !(n && wrap.current?.contains(n))) off(); }}
    >
      <button
        ref={main} type="button" class={`btn${neutral && !armed ? '' : ' dng'} cfb${sm ? ' sm' : ''}${armed ? ' on' : ''}`} disabled={disabled} {...(aria ? { 'aria-label': armed ? `${aria}: confirm` : aria } : {})} {...(testid ? { 'data-testid': testid } : {})}
        onClick={() => { if (armed) { off(); onConfirm(); } else arm(); }}
      >{armed ? `${label}?` : label}</button>
      {armed && <button type="button" class={`btn ghost cfc${sm ? ' sm' : ''}`} onClick={() => { off(); main.current?.focus(); }}>Cancel</button>}
    </span>
  );
}

// -- dialogs and drawers ---------------------------------------------------------------------------
const FOCUSABLE = 'button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],[tabindex]:not([tabindex="-1"])';

/** Modal dialog or side drawer: traps Tab, closes on Esc and a click outside, and gives focus back to its trigger. */
export function Modal({ title, onClose, onEscape, drawer, children, footer, badges, testid }: {
  title: string; onClose: () => void; onEscape?: () => void; drawer?: boolean; children: ComponentChildren; footer?: ComponentChildren; badges?: ComponentChildren; testid?: string;
}) {
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<Element | null>(document.activeElement);
  const titleId = useRef(`dlg-${Math.random().toString(36).slice(2, 8)}`).current;
  useEffect(() => {
    const el = root.current;
    const first = el?.querySelector<HTMLElement>('.mb input:not([disabled]),.mb textarea:not([disabled]),.mb select:not([disabled]),.mb button:not([disabled])') ?? el?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
  }, []);
  // Layout cleanup: runs before the dialog leaves the DOM, so focus moves to the opener instead of being dropped to <body>.
  useLayoutEffect(() => () => {
    const back = trigger.current as HTMLElement | null;
    // The opener may be windowed out or re-keyed by now: fall back to the table.
    const t = back && back !== document.body && back.isConnected ? back : document.querySelector<HTMLElement>('[data-focus-fallback]');
    t?.focus();
  }, []);
  const key = (e: KeyboardEvent) => {
    if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); (onEscape ?? onClose)(); return; }
    if (e.key !== 'Tab' || !root.current) return;
    const f = [...root.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => !x.closest('[hidden]'));
    if (!f.length) return;
    const a = document.activeElement;
    if (e.shiftKey && (a === f[0] || !root.current.contains(a))) { e.preventDefault(); f[f.length - 1]!.focus(); }
    else if (!e.shiftKey && a === f[f.length - 1]) { e.preventDefault(); f[0]!.focus(); }
  };
  return (
    <div class={`scrim${drawer ? ' dw' : ''}`} onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }} onKeyDown={key}>
      <div ref={root} class={drawer ? 'dwr' : 'modal'} role="dialog" aria-modal="true" aria-labelledby={titleId} {...(testid ? { 'data-testid': testid } : {})}>
        <div class="mh">
          <h2 id={titleId}>{title}</h2>{badges}
          <span class="sp" />
          <button type="button" class="ib" aria-label="Close" onClick={onClose}><Icon n="x" size={16} /></button>
        </div>
        {children}
        {footer}
      </div>
    </div>
  );
}

// -- toasts and the live region -------------------------------------------------------------------
interface Toast { id: number; text: string; undo?: () => void }
const toasts = signal<Toast[]>([]);
let toastId = 0;

/** A short confirmation. It is announced through the live region and shown for a few seconds. */
export function toast(text: string, undo?: () => void): void {
  const id = ++toastId;
  toasts.value = [...toasts.value, { id, text, ...(undo ? { undo } : {}) }];
  setTimeout(() => { toasts.value = toasts.value.filter((t) => t.id !== id); }, undo ? 6000 : 2800);
}
export const clearToasts = () => { toasts.value = []; };

export function ToastHost() {
  return (
    <div id="toasts" role="status" aria-live="polite" aria-atomic="false">
      {toasts.value.map((t) => (
        <div class="toast" key={t.id}>
          <span>{t.text}</span>
          {t.undo && <button type="button" class="tu" onClick={() => { toasts.value = toasts.value.filter((x) => x.id !== t.id); t.undo!(); }}>Undo</button>}
        </div>
      ))}
    </div>
  );
}

export function Field({ label, id, children, hidden, cls = '' }: { label: string; id: string; children: ComponentChildren; hidden?: boolean; cls?: string }) {
  return <div class={`fld ${cls}`} hidden={hidden}><label for={id}>{label}</label>{children}</div>;
}

export const targetValue = (e: Event): string => (e.target as HTMLInputElement).value;
