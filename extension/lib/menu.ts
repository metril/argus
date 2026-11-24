import type { MenuCommand, MenuData, MenuGrant } from './bridge-types';

export interface MenuHandlers {
  trigger(c: MenuCommand): Promise<boolean>;
  /** Called synchronously from the click so the permission prompt keeps its user gesture. */
  grant(g: MenuGrant): Promise<boolean> | void;
  close(): void;
}

function mk(root: HTMLElement, tag: string, text?: string, cls?: string) {
  const e = root.ownerDocument.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

export function renderMenu(root: HTMLElement, data: MenuData, h: MenuHandlers) {
  root.textContent = '';
  const byScript = new Map<string, MenuCommand[]>();
  for (const c of data.commands) byScript.set(c.scriptName, [...(byScript.get(c.scriptName) ?? []), c]);
  for (const [name, cmds] of byScript) {
    const box = mk(root, 'div', undefined, 'grp');
    box.append(mk(root, 'h3', name));
    for (const c of cmds) {
      const b = mk(root, 'button', c.name, 'cmd') as HTMLButtonElement;
      if (c.title) b.title = c.title;
      if (c.accessKey) b.setAttribute('accesskey', c.accessKey);
      b.addEventListener('click', async () => {
        const ok = await h.trigger(c);
        if (ok) { if (c.autoClose !== false) h.close(); }
        else box.append(mk(root, 'div', 'Not delivered, reload the page.', 's warn'));
      });
      box.append(b);
    }
    root.append(box);
  }
  for (const g of data.grants) {
    const row = mk(root, 'div', undefined, 'grant');
    row.append(mk(root, 'span', `Script ${g.scriptName} wants your logins for ${g.host}`));
    const b = mk(root, 'button', 'Grant');
    b.addEventListener('click', () => { void h.grant(g); });
    row.append(b);
    root.append(row);
  }
  if (!data.commands.length && !data.grants.length) root.append(mk(root, 'div', 'No userscript commands on this page.', 's mut'));
}
