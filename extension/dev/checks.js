/* Dev-only layout and contrast checks, ported from the mockup's chk.js (window.CK.run(kind) -> { check: [violations] }). */
(function () {
  const R = (e) => e.getBoundingClientRect();
  const vis = (e) => { if (!e || !e.isConnected) return false; const cs = getComputedStyle(e); if (cs.display === 'none' || cs.visibility === 'hidden') return false; const r = R(e); return r.width > 0 && r.height > 0; };
  const desc = (e) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (typeof e.className === 'string' && e.className ? '.' + e.className.trim().split(/\s+/).slice(0, 2).join('.') : '') + ((e.getAttribute('aria-label') || e.textContent || '').trim().slice(0, 18) ? '[' + (e.getAttribute('aria-label') || e.textContent).trim().slice(0, 18) + ']' : '');
  const layer = () => document.querySelector('.scrim .dwr, .scrim .modal') || document.querySelector('.cm') || document.querySelector('.pop') || document.body;

  // c1: blocks of a page share the container's left and right edges
  function edges() {
    const out = [];
    const panel = document.querySelector('.cm-panel');
    if (!panel) return out;
    const pr = R(panel);
    [...panel.children, document.querySelector('.cmh'), document.querySelector('.tabs')].filter((e) => vis(e) && !e.matches('.scrim')).forEach((e) => {
      const r = R(e);
      if (Math.abs(r.left - pr.left) > 1 || Math.abs(r.right - pr.right) > 1) out.push(`${desc(e)} L${(r.left - pr.left).toFixed(1)} R${(r.right - pr.right).toFixed(1)}`);
    });
    return out;
  }
  // c2: no overflow except scroll containers; no control beyond its parent
  function overflow() {
    const out = [];
    const root = layer();
    root.querySelectorAll('*').forEach((e) => {
      if (!vis(e) || e.scrollWidth <= e.clientWidth + 1) return;
      if (e.closest('.tw, .seg, pre, .cfm, .tbr') || e.matches('input, select, textarea, svg, .scrim')) return;
      const cs = getComputedStyle(e);
      if (cs.textOverflow === 'ellipsis' && (cs.overflow === 'hidden' || cs.overflowX === 'hidden')) return;
      if (cs.display === 'inline' || cs.display === 'table-cell' || cs.display === 'contents') return;
      out.push(`overflow ${desc(e)} ${e.scrollWidth}>${e.clientWidth}`);
    });
    root.querySelectorAll('button, input, select, textarea, .sw, .seg, .chip').forEach((e) => {
      if (!vis(e) || e.closest('.seg') && !e.matches('.seg') || e.closest('.tw')) return;
      let p = e.parentElement;
      while (p && p.matches('.cfm, label')) p = p.parentElement;
      if (e.matches('.cfc')) p = e.closest('.mf, .bulk, .li, .aw') || p;
      if (!p) return;
      const r = R(e), pr = R(p);
      if (r.right > pr.right + 1.5) out.push(`beyond parent ${desc(e)} by ${(r.right - pr.right).toFixed(1)} in ${desc(p)}`);
    });
    return out;
  }
  // c3: buttons of one group share a height (and a text baseline when on one line)
  function heights() {
    const out = [], groups = new Map();
    layer().querySelectorAll('.btn, .ib, .chip').forEach((e) => {
      if (!vis(e) || e.closest('.hdr')) return;
      let p = e.parentElement;
      while (p && p.matches('.cfm')) p = p.parentElement;
      (groups.get(p) || groups.set(p, []).get(p)).push(e);
    });
    groups.forEach((arr, p) => {
      const hs = arr.map((x) => Math.round(R(x).height));
      if (Math.max(...hs) - Math.min(...hs) > 1) out.push(`height ${hs.join('/')} in ${desc(p)}`);
    });
    return out;
  }
  // c5: at most one primary button per view
  function primaries() {
    const p = [...layer().querySelectorAll('.btn.pri')].filter(vis);
    return p.length > 1 ? [`${p.length} primaries: ${p.map(desc).join(' | ')}`] : [];
  }
  // c6: tables use the body size; nothing is below 11px
  function fonts() {
    const out = [];
    document.querySelectorAll('.cm td').forEach((e) => { if (R(e).width && getComputedStyle(e).fontSize !== '13px') out.push(`td ${getComputedStyle(e).fontSize} ${desc(e)}`); });
    const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n; const seen = new Set();
    while ((n = tw.nextNode())) {
      if (!n.nodeValue.trim()) continue;
      const p = n.parentElement;
      if (!p || /^(SCRIPT|STYLE)$/.test(p.tagName) || !vis(p)) continue;
      const f = parseFloat(getComputedStyle(p).fontSize);
      if (f < 11) { const k = desc(p); if (!seen.has(k)) { seen.add(k); out.push(`small ${f}px ${k}`); } }
    }
    return out;
  }
  // c9: no horizontal page scroll
  function hscroll() {
    const de = document.documentElement, out = [];
    if (de.scrollWidth > innerWidth + 1) out.push(`doc scrollWidth ${de.scrollWidth} > ${innerWidth}`);
    return out;
  }
  // c10: chips never overlap the toolbar above them
  function chips() {
    const out = [], tb = document.querySelector('.cm .toolbar'), ch = document.querySelector('.cm .chips');
    if (!tb || !ch) return out;
    const t = R(tb);
    ch.querySelectorAll('.chip').forEach((c) => { if (vis(c) && R(c).bottom > t.top && R(c).top < t.bottom + 8 - 0.5) out.push(`chip ${c.textContent} top ${R(c).top.toFixed(1)} < toolbar bottom+8 ${(t.bottom + 8).toFixed(1)}`); });
    return out;
  }
  // c12: cookie rows have one height and one line
  function rows() {
    const out = [], rs = [...document.querySelectorAll('tr[data-row]')].filter(vis);
    if (!rs.length) return out;
    const hs = rs.map((r) => Math.round(R(r).height * 10) / 10);
    if (Math.max(...hs) - Math.min(...hs) > 1) out.push('row heights ' + [...new Set(hs)].join('/'));
    rs.forEach((r) => r.querySelectorAll('td').forEach((td) => { if (td.scrollHeight > td.clientHeight + 1) out.push('wrapped cell ' + desc(td)); }));
    return out;
  }
  // c17: row actions stay inside the viewport and their table
  function reach() {
    const out = [];
    document.querySelectorAll('.sn tbody tr .btn, .sn tbody tr .cfb, .lst .li .cfb, .bulk .btn').forEach((b) => {
      if (!vis(b)) return;
      const r = R(b);
      if (r.right > innerWidth + 0.5 || r.left < -0.5) out.push('outside viewport ' + desc(b));
    });
    return out;
  }
  // c15: Keep list and Greylist have equal heights
  function rulesCards() {
    const cs = [...document.querySelectorAll('.rgrid > .card')].filter((c) => /^(Keep list|Greylist)$/.test(c.querySelector('h3')?.textContent || ''));
    if (cs.length !== 2) return [];
    const a = R(cs[0]), b = R(cs[1]);
    return Math.abs(a.top - b.top) < 2 && Math.abs(a.height - b.height) > 1 ? [`heights ${a.height}/${b.height}`] : [];
  }
  // c8: remove buttons in Rules share a right edge per card
  function removes() {
    const out = [];
    document.querySelectorAll('.rgrid > .card').forEach((c) => {
      const b = [...c.querySelectorAll('.li .cfb')].filter(vis).map((e) => R(e).right);
      if (b.length > 1 && Math.max(...b) - Math.min(...b) > 1) out.push('remove right edge spread in ' + c.querySelector('h3')?.textContent);
    });
    return out;
  }
  // header and body share one column set: header cell x/width equal its body column, the last column ends at the table's edge, the table fills its box, no pill is clipped
  function tables() {
    const out = [];
    document.querySelectorAll('.cm table').forEach((t) => {
      if (!vis(t) || !t.tHead) return;
      const ths = [...t.tHead.rows[0].cells].filter(vis);
      const body = [...t.tBodies[0].rows].find((r) => !r.classList.contains('spacer') && r.cells.length === t.tHead.rows[0].cells.length && vis(r));
      if (!body || t.classList.contains('sn') && innerWidth <= 640) return;
      const tds = [...body.cells];
      ths.forEach((th, i) => {
        const a = R(th), b = R(tds[i]);
        if (Math.abs(a.left - b.left) > 1 || Math.abs(a.width - b.width) > 1) out.push(`${t.className} column ${i} "${th.textContent.trim()}" header x${a.left.toFixed(1)} w${a.width.toFixed(1)} vs body x${b.left.toFixed(1)} w${b.width.toFixed(1)}`);
      });
      const tr = R(t), last = R(ths[ths.length - 1]);
      if (Math.abs(last.right - tr.right) > 1) out.push(`${t.className} last column ends ${last.right.toFixed(1)}, table ends ${tr.right.toFixed(1)}`);
      const tw = t.closest('.tw');
      if (tw && tw.scrollWidth <= tw.clientWidth + 1) {
        const box = R(tw);
        if (Math.abs(tr.right - (box.right - 1)) > 2 || Math.abs(tr.left - (box.left + 1)) > 2) out.push(`${t.className} does not fill its box: table ${tr.left.toFixed(1)}-${tr.right.toFixed(1)}, box ${box.left.toFixed(1)}-${box.right.toFixed(1)}`);
      }
    });
    document.querySelectorAll('.cm .fl').forEach((fl) => {
      if (!vis(fl)) return;
      const cell = fl.closest('td'), c = R(cell);
      [...fl.children].forEach((p) => { if (R(p).right > c.right - 7.5 || R(p).left < c.left) out.push(`pill "${p.textContent}" clipped by its cell (${R(p).right.toFixed(1)} > ${(c.right - 8).toFixed(1)})`); });
    });
    return out;
  }
  // an armed Restore says what it will do: the sentence sits inside the armed row (or its card), within 8px under its buttons
  function restoreWarn() {
    const out = [], armed = [...document.querySelectorAll('.sn .cfm:not(.l).armed')].filter(vis);
    armed.forEach((c) => {
      const w = document.querySelector('.sn .rwarn');
      if (!w) { out.push('armed Restore shows no sentence'); return; }
      const b = R(c.querySelector('.cfb')), r = R(w), tbl = R(c.closest('table'));
      const gap = r.top - b.bottom;
      if (gap < 0 || gap > 8) out.push(`sentence ${gap.toFixed(1)}px under the buttons (want 0 to 8)`);
      if (r.left < tbl.left - 1 || r.right > tbl.right + 1) out.push('sentence outside the table');
      if (parseFloat(getComputedStyle(w).fontSize) !== 12) out.push('sentence is not 12px');
    });
    return out;
  }
  // while a confirm is armed nothing but its button and Cancel paints inside their combined box
  function armedPaint() {
    const out = [];
    document.querySelectorAll('.cfm.armed').forEach((c) => {
      if (!vis(c)) return;
      const parts = [...c.children].filter(vis).map(R);
      const box = { l: Math.min(...parts.map((r) => r.left)), t: Math.min(...parts.map((r) => r.top)), r: Math.max(...parts.map((r) => r.right)), b: Math.max(...parts.map((r) => r.bottom)) };
      const seen = new Set();
      for (let x = box.l + 1; x < box.r; x += 4) for (let y = box.t + 1; y < box.b; y += 4) {
        const e = document.elementFromPoint(x, y);
        if (!e || c.contains(e) || e.contains(c) || seen.has(e)) continue;
        seen.add(e);
        const cs = getComputedStyle(e);
        const a = (v) => { const m = v.match(/rgba?\(([^)]+)\)/); if (!m) return 0; const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return p.length > 3 ? p[3] : 1; };
        const bw = (side) => parseFloat(cs['border' + side + 'Width']) > 0 && cs['border' + side + 'Style'] !== 'none' && a(cs['border' + side + 'Color']) > 0;
        const paints = a(cs.backgroundColor) > 0 || bw('Top') || bw('Bottom') || bw('Left') || bw('Right') || cs.boxShadow !== 'none' || (parseFloat(cs.outlineWidth) > 0 && cs.outlineStyle !== 'none') || [...e.childNodes].some((n) => n.nodeType === 3 && n.nodeValue.trim());
        if (paints) out.push(`${desc(e)} shows inside the armed confirm`);
      }
    });
    return out;
  }
  // masked values are exactly six dots with no ellipsis
  function dots() {
    const out = [];
    document.querySelectorAll('.cm td.val .vbtn:not(.rev)').forEach((b) => { if (!vis(b)) return; if (b.textContent !== '••••••') out.push('mask is ' + b.textContent.length + ' dots'); if (b.scrollWidth > b.clientWidth + 0.5) out.push('mask is clipped'); });
    return out;
  }
  // c14: no blank band between the popup content and its footer
  function popupGap() {
    const m = document.querySelector('.pop .main'), f = document.querySelector('.pop .ftr');
    if (!m || !f) return [];
    const kids = [...m.children].filter(vis), last = kids[kids.length - 1];
    const gap = R(f).top - R(last).bottom;
    return gap > 12.5 || gap < -0.5 ? ['gap between content and footer ' + gap.toFixed(1)] : [];
  }
  // x1: the "Don't decrypt this site" row shares the grid's edges, its button is as tall as the grid's, and it stays within 23px of its resting height
  function popupRow() {
    const g = document.querySelector('.pgrid'), r = document.querySelector('[data-testid=site-bypass]');
    if (!g || !r) return [];
    const gr = R(g), out = [];
    const e = [R(r), ...[...r.children].filter(vis).filter((c) => c.matches('.banner, .btn, .sbp-sk')).map(R)];
    e.forEach((x, i) => { if (Math.abs(x.left - gr.left) > 1 || Math.abs(x.right - gr.right) > 1) out.push(`row part ${i} edges L${(x.left - gr.left).toFixed(1)} R${(x.right - gr.right).toFixed(1)}`); });
    const b = r.querySelector('.btn');
    const gh = Math.round(R(g.querySelector('.btn')).height);
    if (b && Math.abs(Math.round(R(b).height) - gh) > 1) out.push(`button height ${Math.round(R(b).height)} vs grid ${gh}`);
    const h = R(r).height;
    if (h < 51.5 || h > 52 + 23) out.push('row height ' + h.toFixed(1));
    return out;
  }
  // popup grid: equal buttons, two columns
  function popupGrid() {
    const g = document.querySelector('.pgrid');
    if (!g) return [];
    const b = [...g.children].filter(vis).map((e) => R(e));
    const out = [];
    if (b.length !== 4) out.push('grid has ' + b.length + ' buttons');
    if (new Set(b.map((r) => Math.round(r.height))).size > 1) out.push('unequal heights');
    if (new Set(b.map((r) => Math.round(r.width))).size > 1) out.push('unequal widths');
    return out;
  }

  // c11: contrast of every visible text against its composited background
  function parse(c) { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; }
  function over(f, b) { return { r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 }; }
  function bgOf(e) {
    const chain = [];
    for (let n = e; n; n = n.parentElement) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a > 0) { chain.push(c); if (c.a >= 1) break; } }
    let base = { r: 255, g: 255, b: 255, a: 1 };
    const rootBg = parse(getComputedStyle(document.body).backgroundColor); if (rootBg && rootBg.a) base = over(rootBg, base);
    for (let i = chain.length - 1; i >= 0; i--) base = over(chain[i], base);
    return base;
  }
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  function contrast() {
    const out = [], root = layer(), tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT); let n; const seen = new Set();
    const disabledTone = parse(getComputedStyle(document.documentElement).getPropertyValue('--text-3').trim() ? (() => { const d = document.createElement('i'); d.style.color = getComputedStyle(document.documentElement).getPropertyValue('--text-3'); document.body.append(d); const c = getComputedStyle(d).color; d.remove(); return c; })() : 'rgb(0,0,0)');
    while ((n = tw.nextNode())) {
      if (!n.nodeValue.trim()) continue;
      const p = n.parentElement;
      if (!p || !vis(p) || /^(SCRIPT|STYLE|OPTION)$/.test(p.tagName)) continue;
      const cs = getComputedStyle(p);
      let fg = parse(cs.color); if (!fg) continue;
      const bg = bgOf(p);
      fg = over(fg, bg);
      const r = ratio(fg, bg);
      const dis = p.closest(':disabled') || (disabledTone && Math.abs(fg.r - disabledTone.r) + Math.abs(fg.g - disabledTone.g) + Math.abs(fg.b - disabledTone.b) < 3);
      const need = dis ? 3 : 4.5;
      if (r < need) { const k = desc(p) + n.nodeValue.trim().slice(0, 14); if (!seen.has(k)) { seen.add(k); out.push(`${r.toFixed(2)}<${need} ${desc(p)} "${n.nodeValue.trim().slice(0, 24)}"`); } }
    }
    return out;
  }

  window.CK = {
    run(kind) {
      const all = { restoreWarn, armedPaint, dots, tables, edges, overflow, heights, primaries, fonts, hscroll, chips, rows, reach, rulesCards, removes, contrast };
      if (kind === 'popup') return { overflow: overflow(), heights: heights(), fonts: fonts(), hscroll: hscroll(), popupGap: popupGap(), popupGrid: popupGrid(), popupRow: popupRow(), contrast: contrast() };
      const res = {};
      for (const [k, f] of Object.entries(all)) { try { res[k] = f(); } catch (e) { res[k] = ['ERR ' + e.message]; } }
      return res;
    },
  };
})();
