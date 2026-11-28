/** Copies text; rejects when the browser refuses (no permission, no focus). */
export async function copyText(text: string): Promise<void> {
  if (!navigator.clipboard?.writeText) throw new Error('This browser has no clipboard access here.');
  await navigator.clipboard.writeText(text);
}

/** Saves text as a file by building it in the page: no `downloads` permission, nothing leaves the browser. */
export function saveText(name: string, text: string, mime = 'text/plain'): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export const readFileText = (f: File): Promise<string> => f.text();
