// Tests of assets/procedural.js (uBO's procedural operators + Argus compiler/driver) in jsdom.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const SRC = readFileSync(new URL('../assets/procedural.js', import.meta.url), 'utf8');
const sleep = ms => new Promise(r => setTimeout(r, ms));

function page(body, items, { start = true } = {}) {
    const dom = new JSDOM(`<!doctype html><html><head></head><body>${body}</body></html>`, {
        runScripts: 'outside-only', pretendToBeVisual: true, url: 'https://example.test/a/b?q=1',
    });
    const w = dom.window;
    w.eval(SRC + '\n;window.__E = argusProceduralEngine;');
    const engine = w.__E(w, {});
    const ctl = start ? engine.start(items) : null;
    const $ = s => w.document.querySelector(s);
    const $$ = s => [...w.document.querySelectorAll(s)];
    const hidden = el => w.getComputedStyle(el).display === 'none';
    return { w, d: w.document, engine, ctl, $, $$, hidden, close: () => { ctl?.stop(); w.close(); } };
}

test('nested :has with :has-text hides the outer element only when the inner link matches', () => {
    const p = page(`
      <div id=a><a>Sponsored deal</a></div>
      <div id=b><a>Normal</a></div>
      <div id=c><span><a>Sponsored</a></span></div>`,
      [{ s: 'div:has(> a:has-text(Sponsored))', a: 'hide' }]);
    assert.ok(p.hidden(p.$('#a')));
    assert.ok(!p.hidden(p.$('#b')), 'outer element has no text filter of its own');
    assert.ok(!p.hidden(p.$('#c')), '`>` is honoured inside :has');
    p.close();
});

test('operator array form (adblock-rust) with a nested :has-text inside :has', () => {
    const p = page(`<div id=a><a>Ad</a></div><div id=b><a>Hello</a></div>`,
      [{ o: [{ type: 'css-selector', arg: 'div:has(> a:has-text(Ad))' }], a: 'remove' }]);
    assert.equal(p.$('#a'), null);
    assert.ok(p.$('#b'));
    p.close();
});

test(':not(:has-text()) is a nested negation, not a filter on the outer element', () => {
    const p = page(`<div class=card id=a>keep me</div><div class=card id=b>drop me</div>`,
      [{ s: '.card:not(:has-text(keep))', a: 'hide' }]);
    assert.ok(!p.hidden(p.$('#a')));
    assert.ok(p.hidden(p.$('#b')));
    p.close();
});

test('chained operators: has-text then upward(n) and upward(selector)', () => {
    const p = page(`
      <section class=box id=s1><div><p class=t>Promoted</p></div></section>
      <section class=box id=s2><div><p class=t>Plain</p></div></section>
      <article id=r1><div class=in><b class=t>Promoted</b></div></article>`,
      [{ s: 'p.t:has-text(Promoted):upward(2)', a: 'hide' },
       { s: 'b.t:has-text(Promoted):upward(article)', a: 'remove' }]);
    assert.ok(p.hidden(p.$('#s1')));
    assert.ok(!p.hidden(p.$('#s2')));
    assert.equal(p.$('#r1'), null);
    p.close();
});

test(':xpath', () => {
    const p = page(`<div id=w><span id=x>1</span><i id=y>2</i></div><div id=z><span>3</span></div>`,
      [{ s: '#w:xpath(./i)', a: 'hide' },
       { o: [{ type: 'css-selector', arg: '#z' }, { type: 'xpath', arg: './span' }], a: 'hide' }]);
    assert.ok(p.hidden(p.$('#y')));
    assert.ok(!p.hidden(p.$('#x')));
    assert.ok(p.hidden(p.$('#z span')));
    p.close();
});

test(':matches-css, plain and regex values', () => {
    const p = page(`<style>.r{color:red}.g{color:green}</style><p class=r id=a>x</p><p class=g id=b>x</p><p id=c>x</p>`,
      [{ s: 'p:matches-css(color: red)', a: 'hide' },
       { s: 'p:matches-css(color: /^rgb\\(0, 128/)', a: 'remove' }]);
    assert.ok(p.hidden(p.$('#a')) || p.$('#a').hasAttribute('style') === false);
    assert.equal(p.$('#b'), null);
    assert.ok(p.$('#c'));
    p.close();
});

test('actions: remove, style, remove-attr, remove-class', () => {
    const p = page(`<i class=d id=a></i><i class=e id=b>t</i><i class="k1 k2" id=c data-x=1></i>`,
      [{ s: '.d', a: 'remove' },
       { s: '.e:has-text(t)', a: 'style', g: 'color: blue !important' },
       { s: '#c:min-text-length(0)', a: 'remove-attr', g: 'data-x' },
       { o: [{ type: 'css-selector', arg: '#c' }, { type: 'min-text-length', arg: '0' }], a: 'remove-class', g: 'k1' }]);
    assert.equal(p.$('#a'), null);
    assert.equal(p.w.getComputedStyle(p.$('#b')).color, 'rgb(0, 0, 255)');
    assert.equal(p.$('#c').hasAttribute('data-x'), false);
    assert.equal(p.$('#c').className, 'k2');
    p.close();
});

test('action embedded in the selector text (:remove(), :style())', () => {
    const p = page(`<b id=a>Ad</b><b id=b>Ok</b><u id=c>x</u>`,
      [{ s: 'b:has-text(Ad):remove()' }, { s: 'u:style(color: red !important)' }]);
    assert.equal(p.$('#a'), null);
    assert.ok(p.$('#b'));
    assert.equal(p.w.getComputedStyle(p.$('#c')).color, 'rgb(255, 0, 0)');
    p.close();
});

test(':min-text-length, :matches-attr, :matches-prop, :matches-path', () => {
    const p = page(`
      <p id=a>short</p><p id=b>a much longer paragraph of text</p>
      <div id=c data-ad="yes"></div><div id=d data-ad="no"></div>
      <div id=e></div>`,
      [{ s: 'p:min-text-length(10)', a: 'hide' },
       { s: 'div:matches-attr("data-ad"="yes")', a: 'hide' },
       { s: 'div:matches-attr(/^data-/="/n.$/")', a: 'remove' },
       { s: '#e:matches-prop(tagName=DIV):matches-path(/a/b)', a: 'hide' }]);
    assert.ok(!p.hidden(p.$('#a')));
    assert.ok(p.hidden(p.$('#b')));
    assert.ok(p.hidden(p.$('#c')));
    assert.equal(p.$('#d'), null);
    assert.ok(p.hidden(p.$('#e')));
    p.close();
});

test(':others hides everything outside the matched lineage', () => {
    const p = page(`<main id=m><p id=keep>keep</p><p id=gone>gone</p></main><aside id=side>x</aside>`,
      [{ s: '#keep:others()', a: 'hide' }]);
    assert.ok(p.hidden(p.$('#gone')));
    assert.ok(p.hidden(p.$('#side')));
    assert.ok(!p.hidden(p.$('#keep')));
    assert.ok(!p.hidden(p.$('#m')));
    p.close();
});

test('AdGuard spellings: :contains, :nth-ancestor, :-abp-has', () => {
    const p = page(`
      <div id=a><p><span>Ad</span></p></div>
      <div id=b><a>Ad</a></div><div id=c><a>Fine</a></div>`,
      [{ s: 'span:contains(Ad):nth-ancestor(2)', a: 'hide' },
       { s: 'div:-abp-has(a:contains(Ad))', a: 'hide' }]);
    assert.ok(p.hidden(p.$('#a')));
    assert.ok(p.hidden(p.$('#b')));
    assert.ok(!p.hidden(p.$('#c')));
    p.close();
});

test(':watch-attr re-evaluates when the attribute changes', async () => {
    const p = page(`<div id=a data-s=ok>x</div>`,
      [{ s: 'div:watch-attr(data-s):matches-attr(data-s=bad)', a: 'hide' }]);
    assert.ok(!p.hidden(p.$('#a')));
    p.$('#a').setAttribute('data-s', 'bad');
    await sleep(600);
    assert.ok(p.hidden(p.$('#a')));
    p.close();
});

test('a bad selector disables only itself', () => {
    const p = page(`<i class=g id=a>y</i><i class=h id=b>z</i>`,
      [{ s: 'i[:::bad:has-text(x)' }, { s: ':has-text(' }, { s: '!!!:matches-css(nocolon)' },
       { s: '.g:has-text(y)', a: 'hide' },
       { o: [{ type: 'css-selector', arg: '.h' }, { type: 'bogus-op', arg: '1' }] }]);
    assert.ok(p.hidden(p.$('#a')));
    assert.ok(!p.hidden(p.$('#b')));
    p.close();
});

const J = x => JSON.parse(JSON.stringify(x));
test('compiler: nested operators stay nested; CSS after an operator becomes spath', () => {
    const p = page('', null, { start: false });
    const [c] = p.engine.compileItem({ s: 'div:has(> a:has-text(X)) > b:upward(3)' });
    assert.equal(c.selector, 'div');
    assert.deepEqual(J(c.tasks[0]), ['if', { selector: '> a', tasks: [['has-text', 'X']] }]);
    assert.deepEqual(J(c.tasks[1]), ['spath', '> b']);
    assert.deepEqual(J(c.tasks[2]), ['upward', 3]);
    const [n] = p.engine.compileItem({ s: '.x:not(:has-text(Y))' });
    assert.deepEqual(J(n.tasks[0]), ['if-not', { selector: '', tasks: [['has-text', 'Y']] }]);
    const [q] = p.engine.compileItem({ s: 'a:has(.plain)' });
    assert.equal(q.selector, 'a:has(.plain)', 'plain :has stays CSS');
    assert.equal(q.tasks.length, 0);
    p.close();
});

test('mutating page: elements added continuously for 2s all get hidden', async () => {
    const p = page(`<div id=feed></div>`,
      [{ s: '.ad:has-text(Sponsored)', a: 'hide' }, { s: '.row:has(> .ad:has-text(Promo))', a: 'hide' }]);
    const feed = p.$('#feed');
    let n = 0;
    const iv = p.w.setInterval(() => {
        const d = p.d.createElement('div');
        d.className = 'ad'; d.textContent = 'Sponsored ' + n++;
        feed.appendChild(d);
        const r = p.d.createElement('div');
        r.className = 'row'; r.innerHTML = '<span class=ad>Promo</span>';
        feed.appendChild(r);
    }, 10);
    let lagging = 0;
    const t0 = Date.now();
    while (Date.now() - t0 < 2000) {
        await sleep(100);
        // anything older than ~60 insertions must already be processed
        const old = p.$$('.ad').filter(e => /^Sponsored \d+$/.test(e.textContent) && Number(e.textContent.split(' ')[1]) < n - 60);
        if (old.some(e => !p.hidden(e))) lagging++;
    }
    p.w.clearInterval(iv);
    await sleep(500);
    assert.ok(n > 100, `added ${n}`);
    assert.equal(lagging, 0, 'old nodes were left visible while the page kept mutating');
    assert.ok(p.$$('div.ad').every(p.hidden));
    assert.ok(p.$$('.row').every(p.hidden));
    p.close();
});

test('boot script: runs the procedural items from the config at once, leaks no global', async () => {
    const asset = n => readFileSync(new URL('../assets/' + n, import.meta.url), 'utf8');
    // As internal.rs assembles it.
    const boot = '(function(){\nfunction argusBoot(cfg0,nonce0,base0,css0){\n' + SRC + '\n' + asset('natives.js') + '\n' + asset('boot.js') + '\n}\nargusBoot();\n})();\n';
    const cfg = { p: [{ o: [{ type: 'css-selector', arg: '.x' }, { type: 'has-text', arg: 'Ad' }], a: 'hide' }], o: false, t: 't' };
    const dom = new JSDOM(`<!doctype html><html><head><script type="application/json" id="__ab_cfg">${JSON.stringify(cfg)}</script></head><body><b class=x id=a>Ad</b><b class=x id=b>No</b></body></html>`,
        { runScripts: 'outside-only', pretendToBeVisual: true });
    dom.window.eval(boot);
    const d = dom.window.document;
    const late = d.createElement('b'); late.className = 'x'; late.textContent = 'Ad'; d.body.appendChild(late);
    await sleep(400);
    const hid = e => dom.window.getComputedStyle(e).display === 'none';
    assert.ok(hid(d.getElementById('a')) && hid(late));
    assert.ok(!hid(d.getElementById('b')));
    assert.equal(typeof dom.window.argusProceduralEngine, 'undefined');
    dom.window.close();
});

test('plain :-abp-has, :if and :if-not (no procedural operator inside) are operators, not CSS', () => {
    const p = page(`
      <div id=a class=t><i class=k></i></div><div id=b class=t><i></i></div>
      <div id=c class=u><i class=k></i></div><div id=d class=v><i></i></div>`,
      [{ s: 'div.t:-abp-has(.k)', a: 'hide' },
       { s: 'div.u:if(.k)', a: 'hide' },
       { s: 'div.v:if-not(.k)', a: 'hide' }]);
    assert.ok(p.hidden(p.$('#a')));
    assert.ok(!p.hidden(p.$('#b')));
    assert.ok(p.hidden(p.$('#c')));
    assert.ok(p.hidden(p.$('#d')));
    p.close();
});

test('an element is restored when it stops matching', () => {
    const p = page(`<div id=a class=x>Ad</div>`, [{ s: '.x:has-text(Ad)', a: 'hide' }]);
    assert.ok(p.hidden(p.$('#a')));
    p.$('#a').textContent = 'fine';
    p.ctl.run();
    assert.ok(!p.hidden(p.$('#a')));
    p.close();
});

test('unsafe :style() blocks are refused in the page', () => {
    const p = page(`<b id=a>x</b><b id=b>x</b><b id=c>x</b><b id=d>x</b>`,
      [{ s: '#a:style(background: url(https://evil.test/x))' },
       { s: '#b:style(color: red; /* )' },
       { s: '#c:style(background: image-set("https://evil.test/y" 1x))' },
       { s: '#d:style(color: red !important)' }]);
    for (const id of ['a', 'b', 'c']) assert.equal(p.$('#' + id).getAttributeNames().filter(n => n !== 'id').length, 0, id);
    assert.equal(p.w.getComputedStyle(p.$('#d')).color, 'rgb(255, 0, 0)');
    p.close();
});
