/* Argus in-page procedural cosmetic engine.
 *
 * The PSelector* classes below (the procedural operators and their semantics) are uBlock Origin's
 * src/js/contentscript-extra.js at commit 5934db2a0437a50182c4a8f3da2e0941cf806253, GPL-3.0-or-later,
 * Copyright (C) 2014-present Raymond Hill, https://github.com/gorhill/uBlock.
 * Modified by Argus: wrapped in a factory taking the window (no vAPI global), triggerDOMChange calls
 * opts.onChange, and uBO's ProceduralFilterer/vAPI.domFilterer are replaced by the driver and the
 * selector compiler at the bottom of this file. See vendor/ubo-procedural/README.md.
 */
function argusProceduralEngine(window, opts){
"use strict";
opts = opts || {};
const document = window.document, self = window, XPathResult = window.XPathResult;
const MutationObserver = window.MutationObserver;
const nonVisualElements = {
    head: true,
    link: true,
    meta: true,
    script: true,
    style: true,
};

const regexFromString = (s, exact = false) => {
    if ( s === '' ) { return /^/; }
    const match = /^\/(.+)\/([imu]*)$/.exec(s);
    if ( match !== null ) {
        return new RegExp(match[1], match[2] || undefined);
    }
    const reStr = s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(exact ? `^${reStr}$` : reStr);
};

const triggerDOMChange = ( ) => { opts.onChange && opts.onChange(); };

// 'P' stands for 'Procedural'

class PSelectorTask {
    begin() {
    }
    end() {
    }
}

class PSelectorVoidTask extends PSelectorTask {
    constructor(task) {
        super();
        console.info(`uBO: :${task[0]}() operator does not exist`);
    }
    transpose() {
    }
}

class PSelectorContentTask extends PSelectorTask {
    constructor(task) {
        super();
        this.selector = task[1];
    }
    transpose(node, output) {
        const root = node.content;
        if ( typeof root?.querySelectorAll !== 'function' ) { return; }
        const nodes = root.querySelectorAll(this.selector);
        output.push(...nodes);
    }
}

class PSelectorHasTextTask extends PSelectorTask {
    constructor(task) {
        super();
        this.needle = regexFromString(task[1]);
    }
    transpose(node, output) {
        if ( this.needle.test(node.textContent) ) {
            output.push(node);
        }
    }
}

class PSelectorIfTask extends PSelectorTask {
    constructor(task) {
        super();
        this.pselector = new PSelector(task[1]);
    }
    transpose(node, output) {
        if ( this.pselector.test(node) === this.target ) {
            output.push(node);
        }
    }
}
PSelectorIfTask.prototype.target = true;

class PSelectorIfNotTask extends PSelectorIfTask {
}
PSelectorIfNotTask.prototype.target = false;

class PSelectorMatchesAttrTask extends PSelectorTask {
    constructor(task) {
        super();
        this.reAttr = regexFromString(task[1].attr, true);
        this.reValue = regexFromString(task[1].value, true);
    }
    transpose(node, output) {
        if ( typeof node.getAttributeNames !== 'function' ) { return; }
        const attrs = node.getAttributeNames();
        for ( const attr of attrs ) {
            if ( this.reAttr.test(attr) === false ) { continue; }
            if ( this.reValue.test(node.getAttribute(attr)) === false ) { continue; }
            output.push(node);
        }
    }
}

class PSelectorMatchesCSSTask extends PSelectorTask {
    constructor(task) {
        super();
        this.name = task[1].name;
        this.pseudo = task[1].pseudo ? `::${task[1].pseudo}` : null;
        let arg0 = task[1].value, arg1;
        if ( Array.isArray(arg0) ) {
            arg1 = arg0[1]; arg0 = arg0[0];
        }
        this.value = new RegExp(arg0, arg1);
    }
    transpose(node, output) {
        const style = window.getComputedStyle(node, this.pseudo);
        if ( style !== null && this.value.test(style[this.name]) ) {
            output.push(node);
        }
    }
}
class PSelectorMatchesCSSAfterTask extends PSelectorMatchesCSSTask {
    constructor(task) {
        super(task);
        this.pseudo = '::after';
    }
}

class PSelectorMatchesCSSBeforeTask extends PSelectorMatchesCSSTask {
    constructor(task) {
        super(task);
        this.pseudo = '::before';
    }
}

class PSelectorMatchesMediaTask extends PSelectorTask {
    constructor(task) {
        super();
        this.mql = window.matchMedia(task[1]);
        if ( this.mql.media === 'not all' ) { return; }
        this.mql.addEventListener('change', triggerDOMChange);
    }
    transpose(node, output) {
        if ( this.mql.matches === false ) { return; }
        output.push(node);
    }
}

class PSelectorMatchesPathTask extends PSelectorTask {
    constructor(task) {
        super();
        this.needle = regexFromString(
            task[1].replace(/\P{ASCII}/gu, s => encodeURIComponent(s))
        );
        if ( PSelectorMatchesPathTask.#listener ) { return; }
        PSelectorMatchesPathTask.#listener = true;
        if ( Boolean(self.navigation) === false ) { return; }
        self.navigation.addEventListener('navigate', triggerDOMChange);
    }
    transpose(node, output) {
        if ( this.needle.test(self.location.pathname + self.location.search) ) {
            output.push(node);
        }
    }
    static #listener;
}

class PSelectorMatchesPropTask extends PSelectorTask {
    constructor(task) {
        super();
        this.props = task[1].attr.split('.');
        this.reValue = task[1].value !== ''
            ? regexFromString(task[1].value, true)
            : null;
    }
    transpose(node, output) {
        let value = node;
        for ( const prop of this.props ) {
            if ( value === undefined ) { return; }
            if ( value === null ) { return; }
            value = value[prop];
        }
        if ( this.reValue === null ) {
            if ( value === undefined ) { return; }
        } else if ( this.reValue.test(value) === false ) {
            return;
        }
        output.push(node);
    }
}

class PSelectorMinTextLengthTask extends PSelectorTask {
    constructor(task) {
        super();
        this.min = task[1];
    }
    transpose(node, output) {
        if ( node.textContent.length >= this.min ) {
            output.push(node);
        }
    }
}

class PSelectorOthersTask extends PSelectorTask {
    constructor() {
        super();
        this.targets = new Set();
    }
    begin() {
        this.targets.clear();
    }
    end(output) {
        const toKeep = new Set(this.targets);
        const toDiscard = new Set();
        const body = document.body;
        const head = document.head;
        let discard = null;
        for ( let keep of this.targets ) {
            while ( keep !== null && keep !== body && keep !== head ) {
                toKeep.add(keep);
                toDiscard.delete(keep);
                discard = keep.previousElementSibling;
                while ( discard !== null ) {
                    if ( nonVisualElements[discard.localName] !== true ) {
                        if ( toKeep.has(discard) === false ) {
                            toDiscard.add(discard);
                        }
                    }
                    discard = discard.previousElementSibling;
                }
                discard = keep.nextElementSibling;
                while ( discard !== null ) {
                    if ( nonVisualElements[discard.localName] !== true ) {
                        if ( toKeep.has(discard) === false ) {
                            toDiscard.add(discard);
                        }
                    }
                    discard = discard.nextElementSibling;
                }
                keep = keep.parentElement;
            }
        }
        for ( discard of toDiscard ) {
            output.push(discard);
        }
        this.targets.clear();
    }
    transpose(candidate) {
        for ( const target of this.targets ) {
            if ( target.contains(candidate) ) { return; }
            if ( candidate.contains(target) ) {
                this.targets.delete(target);
            }
        }
        this.targets.add(candidate);
    }
}

class PSelectorShadowTask extends PSelectorTask {
    constructor(task) {
        super();
        this.selector = task[1];
    }
    transpose(node, output) {
        const root = this.openOrClosedShadowRoot(node);
        if ( root === null ) { return; }
        const nodes = root.querySelectorAll(this.selector);
        output.push(...nodes);
    }
    get openOrClosedShadowRoot() {
        if ( PSelectorShadowTask.openOrClosedShadowRoot !== undefined ) {
            return PSelectorShadowTask.openOrClosedShadowRoot;
        }
        const { chrome }  = self;
        if ( typeof chrome === 'object' && chrome !== null ) {
            if ( chrome.dom instanceof Object ) {
                if ( typeof chrome.dom.openOrClosedShadowRoot === 'function' ) {
                    PSelectorShadowTask.openOrClosedShadowRoot =
                        chrome.dom.openOrClosedShadowRoot;
                    return PSelectorShadowTask.openOrClosedShadowRoot;
                }
            }
        }
        PSelectorShadowTask.openOrClosedShadowRoot = node =>
            node.openOrClosedShadowRoot || null;
        return PSelectorShadowTask.openOrClosedShadowRoot;
    }
}

// https://github.com/AdguardTeam/ExtendedCss/issues/31#issuecomment-302391277
//   Prepend `:scope ` if needed.
class PSelectorSpathTask extends PSelectorTask {
    constructor(task) {
        super();
        this.spath = task[1];
        this.nth = /^(?:\s*[+~]|:)/.test(this.spath);
        if ( this.nth ) { return; }
        if ( /^\s*>/.test(this.spath) ) {
            this.spath = `:scope ${this.spath.trim()}`;
        }
    }
    transpose(node, output) {
        const nodes = this.nth
            ? PSelectorSpathTask.qsa(node, this.spath)
            : node.querySelectorAll(this.spath);
        for ( const node of nodes ) {
            output.push(node);
        }
    }
    // Helper method for other operators.
    static qsa(node, selector) {
        const parent = node.parentElement;
        if ( parent === null ) { return []; }
        let pos = 1;
        for (;;) {
            node = node.previousElementSibling;
            if ( node === null ) { break; }
            pos += 1;
        }
        return parent.querySelectorAll(
            `:scope > :nth-child(${pos})${selector}`
        );
    }
}

class PSelectorUpwardTask extends PSelectorTask {
    constructor(task) {
        super();
        const arg = task[1];
        if ( typeof arg === 'number' ) {
            this.i = arg;
        } else {
            this.s = arg;
        }
    }
    transpose(node, output) {
        if ( this.s !== '' ) {
            const parent = node.parentElement;
            if ( parent === null ) { return; }
            node = parent.closest(this.s);
            if ( node === null ) { return; }
        } else {
            let nth = this.i;
            for (;;) {
                node = node.parentElement;
                if ( node === null ) { return; }
                nth -= 1;
                if ( nth === 0 ) { break; }
            }
        }
        output.push(node);
    }
}
PSelectorUpwardTask.prototype.i = 0;
PSelectorUpwardTask.prototype.s = '';

class PSelectorWatchAttrs extends PSelectorTask {
    constructor(task) {
        super();
        this.observed = new WeakSet();
        this.observerOptions = {
            attributes: true,
            subtree: true,
        };
        const attrs = task[1];
        if ( Array.isArray(attrs) && attrs.length !== 0 ) {
            this.observerOptions.attributeFilter = task[1];
        }
    }
    transpose(node, output) {
        output.push(node);
        if ( this.observed.has(node) ) { return; }
        if ( PSelectorWatchAttrs.#observer === undefined ) {
            PSelectorWatchAttrs.#observer = new MutationObserver(triggerDOMChange);
        }
        PSelectorWatchAttrs.#observer.observe(node, this.observerOptions);
        this.observed.add(node);
    }
    static #observer;
}

class PSelectorXpathTask extends PSelectorTask {
    constructor(task) {
        super();
        this.xpe = document.createExpression(task[1], null);
        this.xpr = null;
    }
    transpose(node, output) {
        this.xpr = this.xpe.evaluate(
            node,
            XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE,
            this.xpr
        );
        let j = this.xpr.snapshotLength;
        while ( j-- ) {
            const node = this.xpr.snapshotItem(j);
            if ( node.nodeType === 1 ) {
                output.push(node);
            }
        }
    }
}

class PSelector {
    constructor(o) {
        this.selector = o.selector;
        this.tasks = [];
        const tasks = [];
        if ( Array.isArray(o.tasks) === false ) { return; }
        for ( const task of o.tasks ) {
            const ctor = this.operatorToTaskMap.get(task[0]) || PSelectorVoidTask;
            tasks.push(new ctor(task));
        }
        this.tasks = tasks;
    }
    prime(input) {
        const root = input || document;
        if ( this.selector === '' ) { return [ root ]; }
        if ( input !== document ) {
            const c0 = this.selector.charCodeAt(0);
            if ( c0 === 0x2B /* + */ || c0 === 0x7E /* ~ */ ) {
                return Array.from(PSelectorSpathTask.qsa(input, this.selector));
            } else if ( c0 === 0x3E /* > */ ) {
                return Array.from(input.querySelectorAll(`:scope ${this.selector}`));
            }
        }
        return Array.from(root.querySelectorAll(this.selector));
    }
    exec(input) {
        let nodes = this.prime(input);
        for ( const task of this.tasks ) {
            if ( nodes.length === 0 ) { break; }
            const transposed = [];
            task.begin();
            for ( const node of nodes ) {
                task.transpose(node, transposed);
            }
            task.end(transposed);
            nodes = transposed;
        }
        return nodes;
    }
    test(input) {
        const nodes = this.prime(input);
        for ( const node of nodes ) {
            let output = [ node ];
            for ( const task of this.tasks ) {
                const transposed = [];
                task.begin();
                for ( const node of output ) {
                    task.transpose(node, transposed);
                }
                task.end(transposed);
                output = transposed;
                if ( output.length === 0 ) { break; }
            }
            if ( output.length !== 0 ) { return true; }
        }
        return false;
    }
}
PSelector.prototype.operatorToTaskMap = new Map([
    [ 'content', PSelectorContentTask ],
    [ 'has', PSelectorIfTask ],
    [ 'has-text', PSelectorHasTextTask ],
    [ 'if', PSelectorIfTask ],
    [ 'if-not', PSelectorIfNotTask ],
    [ 'matches-attr', PSelectorMatchesAttrTask ],
    [ 'matches-css', PSelectorMatchesCSSTask ],
    [ 'matches-css-after', PSelectorMatchesCSSAfterTask ],
    [ 'matches-css-before', PSelectorMatchesCSSBeforeTask ],
    [ 'matches-media', PSelectorMatchesMediaTask ],
    [ 'matches-path', PSelectorMatchesPathTask ],
    [ 'matches-prop', PSelectorMatchesPropTask ],
    [ 'min-text-length', PSelectorMinTextLengthTask ],
    [ 'not', PSelectorIfNotTask ],
    [ 'others', PSelectorOthersTask ],
    [ 'shadow', PSelectorShadowTask ],
    [ 'spath', PSelectorSpathTask ],
    [ 'upward', PSelectorUpwardTask ],
    [ 'watch-attr', PSelectorWatchAttrs ],
    [ 'xpath', PSelectorXpathTask ],
]);

class PSelectorRoot extends PSelector {
    constructor(o) {
        super(o);
        this.budget = 200; // I arbitrary picked a 1/5 second
        this.raw = o.raw;
        this.cost = 0;
        this.lastAllowanceTime = 0;
        this.action = o.action;
    }
    prime(input) {
        try {
            return super.prime(input);
        } catch {
        }
        return [];
    }
}
PSelectorRoot.prototype.hit = false;

/******************************************************************************/
/* Argus glue: selector text / adblock-rust operator arrays -> uBO's compiled form
   ({selector, tasks:[[op, arg], ...], action}), and the driver that applies them. */

const OPS = new Set([
    'has-text', 'contains', '-abp-contains', 'min-text-length', 'matches-path',
    'matches-media', 'matches-css', 'matches-css-before', 'matches-css-after',
    '-abp-properties', 'properties', 'matches-attr', 'matches-prop',
    'matches-property', 'upward', 'nth-ancestor', 'xpath', 'shadow', 'spath',
    'others', 'watch-attr', 'content', 'has', '-abp-has', 'if', 'if-not', 'not',
]);
const NESTING = new Set([ 'has', '-abp-has', 'if', 'if-not', 'not' ]);
const ACTIONS = new Set([ 'remove', 'style', 'remove-attr', 'remove-class' ]);
const PROC_RE = /:(?:has-text|contains|-abp-contains|min-text-length|matches-[a-z-]+|-abp-properties|properties|upward|nth-ancestor|xpath|shadow|spath|others|watch-attr|-abp-has|if|if-not)\b/;

const matchParen = (s, open) => {
    let depth = 0;
    for ( let i = open; i < s.length; i++ ) {
        const c = s[i];
        if ( c === '\\' ) { i++; continue; }
        if ( c === '(' ) { depth++; }
        else if ( c === ')' && --depth === 0 ) { return i; }
    }
    throw new Error('unbalanced parenthesis');
};

const skipBracket = (s, open) => {
    let q = '';
    for ( let i = open + 1; i < s.length; i++ ) {
        const c = s[i];
        if ( c === '\\' ) { i++; continue; }
        if ( q !== '' ) { if ( c === q ) { q = ''; } continue; }
        if ( c === '"' || c === "'" ) { q = c; }
        else if ( c === ']' ) { return i + 1; }
    }
    return s.length;
};

// Split on top-level commas (outside parentheses, brackets and escapes).
const splitTop = s => {
    const out = [];
    let depth = 0, start = 0;
    for ( let i = 0; i < s.length; i++ ) {
        const c = s[i];
        if ( c === '\\' ) { i++; }
        else if ( c === '[' ) { i = skipBracket(s, i) - 1; }
        else if ( c === '(' ) { depth++; }
        else if ( c === ')' ) { depth--; }
        else if ( c === ',' && depth === 0 ) { out.push(s.slice(start, i)); start = i + 1; }
    }
    out.push(s.slice(start));
    return out.map(x => x.trim()).filter(x => x !== '');
};

// Only `:has()` and `:not()` may stay native CSS, and only with a pure-CSS argument; the
// others (`:-abp-has`, `:if`, `:if-not`) are not CSS at all.
const NATIVE_OK = new Set([ 'has', 'not' ]);
const isOperator = (name, arg) =>
    OPS.has(name) && (NATIVE_OK.has(name) === false || PROC_RE.test(arg)) ||
    ACTIONS.has(name);

// Defensive twin of ext_rules::is_safe_style: a style block must not fetch anything or be able to
// end its own rule / comment out the rules after it in the shared sheet.
const safeStyle = s => {
    if ( s.length > 2048 || /[\\{}@<\u0000-\u0008\u000a-\u001f\u007f]/.test(s) ) { return false; }
    if ( s.includes('/*') || s.includes('*/') ) { return false; }
    if ( /-moz-binding|behavior/i.test(s) ) { return false; }
    return /(?:^|[^a-z-])(?:url|image-set|src|image|cross-fade|element|paint|attr|expression)\s*\(/i.test(s) === false;
};

// Selector text -> [{css}, {op, arg}, ...]. Pseudo-classes that are plain CSS stay in the css
// parts, including `:has()`/`:not()` whose argument holds no procedural operator.
const tokenize = sel => {
    const out = [];
    let cur = '', i = 0;
    const n = sel.length;
    const flush = ( ) => { if ( cur !== '' ) { out.push({ css: cur }); cur = ''; } };
    while ( i < n ) {
        const c = sel[i];
        if ( c === '\\' ) { cur += sel.slice(i, i + 2); i += 2; continue; }
        if ( c === '[' ) { const j = skipBracket(sel, i); cur += sel.slice(i, j); i = j; continue; }
        if ( c === ':' && sel[i+1] !== ':' && sel[i-1] !== ':' ) {
            const m = /^:([a-zA-Z-]+)/.exec(sel.slice(i, i + 40));
            if ( m !== null ) {
                const name = m[1].toLowerCase();
                const after = i + m[0].length;
                if ( sel[after] === '(' ) {
                    const end = matchParen(sel, after);
                    const arg = sel.slice(after + 1, end);
                    if ( isOperator(name, arg) ) {
                        flush();
                        out.push({ op: name, arg });
                    } else {
                        cur += sel.slice(i, end + 1);
                    }
                    i = end + 1;
                    continue;
                }
                if ( name === 'others' ) { flush(); out.push({ op: name, arg: '' }); i = after; continue; }
            }
        }
        cur += c; i++;
    }
    flush();
    return out;
};

const unquote = s => {
    s = s.trim();
    const q = s.charAt(0);
    if ( s.length > 1 && (q === '"' || q === "'") && s.charAt(s.length-1) === q ) {
        return s.slice(1, -1).replace(/\\(["'])/g, '$1');
    }
    return s;
};

// A pattern: `/regex/flags` as is, anything else a literal where `*` matches anything.
const patternSource = v => {
    const m = /^\/(.+)\/([imu]*)$/.exec(v);
    if ( m !== null ) { return m[2] ? [ m[1], m[2] ] : m[1]; }
    return '^' + v.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
};

const nested = arg => {
    const { selector, tasks } = assemble(tokenize(arg.trim()), false);
    return { selector, tasks };
};

const makeTask = (name, arg) => {
    switch ( name ) {
    case 'has-text': case 'contains': case '-abp-contains':
        return [ 'has-text', arg ];
    case 'has': case '-abp-has': case 'if':
        return [ 'if', nested(arg) ];
    case 'if-not': case 'not':
        return [ 'if-not', nested(arg) ];
    case 'min-text-length': {
        const n = parseInt(arg, 10);
        if ( n >= 0 === false ) { throw new Error('bad min-text-length'); }
        return [ name, n ];
    }
    case 'matches-path': case 'matches-media':
        return [ name, unquote(arg) ];
    case 'matches-css': case 'matches-css-before': case 'matches-css-after':
    case '-abp-properties': case 'properties': {
        const d = unquote(arg);
        const ix = d.indexOf(':');
        if ( ix < 1 ) { throw new Error('bad matches-css'); }
        const t = name === 'matches-css-before' || name === 'matches-css-after' ? name : 'matches-css';
        return [ t, {
            name: d.slice(0, ix).trim(),
            pseudo: null,
            value: patternSource(unquote(d.slice(ix + 1))),
        } ];
    }
    case 'matches-attr': {
        const m = /^("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^=]*)(?:=([\s\S]*))?$/.exec(arg.trim());
        const attr = m === null ? '' : unquote(m[1]);
        if ( attr === '' ) { throw new Error('bad matches-attr'); }
        return [ 'matches-attr', { attr, value: m[2] === undefined ? '' : unquote(m[2]) } ];
    }
    case 'matches-prop': case 'matches-property': {
        const ix = arg.indexOf('=');
        const attr = (ix === -1 ? arg : arg.slice(0, ix)).trim();
        if ( attr === '' ) { throw new Error('bad matches-prop'); }
        return [ 'matches-prop', { attr, value: ix === -1 ? '' : unquote(arg.slice(ix + 1)) } ];
    }
    case 'upward': case 'nth-ancestor': {
        const a = arg.trim();
        if ( /^\d+$/.test(a) ) {
            const n = parseInt(a, 10);
            if ( n < 1 || n > 255 ) { throw new Error('bad upward'); }
            return [ 'upward', n ];
        }
        if ( name === 'nth-ancestor' || a === '' ) { throw new Error('bad nth-ancestor'); }
        return [ 'upward', a ];
    }
    case 'xpath': case 'shadow': case 'spath': case 'content':
        return [ name, arg.trim() ];
    case 'others':
        return [ 'others' ];
    case 'watch-attr':
        return [ 'watch-attr', arg.split(/[\s,]+/).filter(x => x !== '') ];
    default:
        throw new Error(`unknown operator ${name}`);
    }
};

// Tokens -> { selector, tasks, action }. CSS after an operator becomes a spath task (uBO's way).
const assemble = (tokens, top) => {
    let selector = '', action, seenOp = false;
    const tasks = [];
    for ( const t of tokens ) {
        if ( action !== undefined ) { throw new Error('operator after action'); }
        if ( t.css !== undefined ) {
            if ( seenOp === false ) { selector += t.css; }
            else if ( t.css.trim() !== '' ) { tasks.push([ 'spath', t.css.trim() ]); }
        } else if ( ACTIONS.has(t.op) ) {
            action = t.arg === '' && t.op === 'remove' ? [ 'remove' ] : [ t.op, t.arg ];
        } else {
            seenOp = true;
            tasks.push(makeTask(t.op, t.arg));
        }
    }
    selector = selector.trim();
    if ( top && selector === '' ) { selector = '*'; }
    return { selector, tasks, action };
};

const ACTION_NAMES = new Set([ 'remove', 'style', 'remove-attr', 'remove-class' ]);

// One config item -> compiled selectors. Items are
//   { o: [{type, arg}, ...] (adblock-rust's `selector`) | s: selector text, a: action, g: argument }.
const compileItem = item => {
    const lists = Array.isArray(item.o)
        ? [ item.o.flatMap(op => op.type === 'css-selector'
            ? tokenize(String(op.arg))
            : [ { op: String(op.type), arg: String(op.arg === undefined ? '' : op.arg) } ]) ]
        : splitTop(String(item.s)).map(tokenize);
    const out = [];
    for ( const tokens of lists ) {
        const c = assemble(tokens, true);
        if ( c.action === undefined && ACTION_NAMES.has(item.a) ) {
            c.action = item.a === 'remove' ? [ 'remove' ] : [ item.a, String(item.g === undefined ? '' : item.g) ];
        }
        c.raw = JSON.stringify([ c.selector, c.tasks, c.action ]);
        out.push(c);
    }
    return out;
};

/******************************************************************************/
/* Driver: runs the compiled selectors, applies their actions, and re-runs on DOM changes,
   throttled (at most one pass per `gap` ms, aligned to a frame) so that a page that mutates
   continuously still gets its new nodes processed. */

const randomToken = ( ) => 'a' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
const HIDE_STYLE = 'display:none!important;';

const start = items => {
    const selectors = [];
    for ( const item of items || [] ) {
        let list;
        try { list = compileItem(item); } catch { continue; }
        for ( const c of list ) {
            try { selectors.push(new PSelectorRoot(c)); } catch { }
        }
    }
    const result = { selectors: selectors.length, run: ( ) => { }, stop: ( ) => { } };
    if ( selectors.length === 0 ) { return result; }

    const masterToken = randomToken();
    const styleTokenMap = new Map();
    let styledNodes = new Set();
    let sheetEl = null;

    const addCss = css => {
        if ( typeof opts.addCss === 'function' ) { opts.addCss(css); return; }
        if ( sheetEl === null ) {
            sheetEl = document.createElement('style');
            if ( opts.nonce ) { sheetEl.setAttribute('nonce', opts.nonce); }
            (document.head || document.documentElement).appendChild(sheetEl);
        }
        sheetEl.appendChild(document.createTextNode(css));
    };
    const styleToken = style => {
        let t = styleTokenMap.get(style);
        if ( t !== undefined ) { return t; }
        if ( safeStyle(style) === false ) { return ''; }
        t = randomToken();
        styleTokenMap.set(style, t);
        addCss(`[${masterToken}][${t}]{${style}}\n`);
        return t;
    };

    const processNodes = (nodes, action) => {
        const op = action && action[0] || '';
        const arg = op !== '' ? action[1] : '';
        switch ( op ) {
        case '':
        case 'style': {
            const t = styleToken(arg === '' ? HIDE_STYLE : arg);
            if ( t === '' ) { break; }
            for ( const node of nodes ) {
                node.setAttribute(masterToken, '');
                node.setAttribute(t, '');
                styledNodes.add(node);
            }
            break;
        }
        case 'remove': {
            for ( const node of nodes ) {
                if ( node === document.documentElement || node === document.body || node === document.head ) { continue; }
                node.remove();
                node.textContent = '';
            }
            break;
        }
        case 'remove-attr': {
            const reAttr = regexFromString(arg, true);
            for ( const node of nodes ) {
                for ( const name of node.getAttributeNames() ) {
                    if ( reAttr.test(name) === false ) { continue; }
                    node.removeAttribute(name);
                }
            }
            break;
        }
        case 'remove-class': {
            const reClass = regexFromString(arg, true);
            for ( const node of nodes ) {
                const cl = node.classList;
                for ( const name of cl.values() ) {
                    if ( reClass.test(name) === false ) { continue; }
                    cl.remove(name);
                }
            }
            break;
        }
        default:
            break;
        }
    };

    // A pass: every selector runs; nodes that no longer match are unstyled (uBO's commitNow).
    const commitNow = ( ) => {
        const toUnstyle = styledNodes;
        styledNodes = new Set();
        let t0 = Date.now();
        for ( const ps of selectors ) {
            const allowance = Math.floor((t0 - ps.lastAllowanceTime) / 2000);
            if ( allowance >= 1 ) {
                ps.budget += allowance * 50;
                if ( ps.budget > 200 ) { ps.budget = 200; }
                ps.lastAllowanceTime = t0;
            }
            if ( ps.budget <= 0 ) { continue; }
            let nodes = [];
            try { nodes = ps.exec(); } catch { }
            const t1 = Date.now();
            ps.budget += t0 - t1;
            if ( ps.budget < -500 ) { ps.budget = -0x7FFFFFFF; }
            t0 = t1;
            if ( nodes.length === 0 ) { continue; }
            ps.hit = true;
            try { processNodes(nodes, ps.action); } catch { }
        }
        for ( const node of toUnstyle ) {
            if ( styledNodes.has(node) ) { continue; }
            node.removeAttribute(masterToken);
        }
    };

    const gap = opts.gap || 100;
    let pending = false, last = 0, cost = 0, timer = 0, stopped = false, cycle = 0;
    const fire = id => {
        if ( pending === false || stopped || (id !== undefined && id !== cycle) ) { return; }
        pending = false;
        clearTimeout(timer);
        const t = Date.now();
        try { commitNow(); } catch { }
        last = Date.now();
        cost = last - t;
    };
    const schedule = ( ) => {
        if ( pending || stopped ) { return; }
        pending = true;
        const id = ++cycle;
        const wait = Math.max(0, last + Math.max(gap, cost * 3) - Date.now());
        // Frame-aligned when the page is visible; the timer is the fallback (hidden tabs).
        timer = setTimeout(( ) => fire(id), wait + 250);
        setTimeout(( ) => {
            if ( typeof window.requestAnimationFrame === 'function' ) { window.requestAnimationFrame(( ) => fire(id)); }
            else { fire(id); }
        }, wait);
    };
    opts.onChange = schedule;

    let mo = null;
    try {
        mo = new MutationObserver(schedule);
        mo.observe(document, { childList: true, subtree: true });
    } catch { }
    const runNow = ( ) => { pending = true; fire(); };
    runNow();
    try {
        document.addEventListener('DOMContentLoaded', runNow, { once: true });
        window.addEventListener('load', runNow, { once: true });
    } catch { }
    result.run = runNow;
    result.stop = ( ) => { stopped = true; if ( mo ) { mo.disconnect(); } clearTimeout(timer); };
    return result;
};

return { start, compileItem, regexFromString };
}
