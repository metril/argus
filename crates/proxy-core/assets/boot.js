/* Body of `argusBoot(cfg0, nonce0, base0, css0)` (see internal.rs): procedural.js, natives.js and
   this file share one function scope. The page runs it with no arguments (config from the
   `__ab_cfg` element); friendly frames (about:blank, srcdoc, blob:) get the function's source in an
   inline script with the arguments filled in. */
/* Once per document (a window survives about:blank -> srcdoc; its document does not). A symbol key cannot be clobbered by markup. */
var BK=Symbol.for('argus.boot');if(document[BK])return;try{Object.defineProperty(document,BK,{value:1,configurable:true});}catch(e){}
var cfg=cfg0||{};if(!cfg0){try{cfg=JSON.parse(document.getElementById('__ab_cfg').textContent)||{};}catch(e){}}
var base=base0||'';
var pageUrl=cfg.u||location.href;
/* Runtime for scriptlets/snippets that have no uBO equivalent: self.__argusRuntime.run(kind,name,args).
   Calls made before this script ran may be queued by the page injection in __argusRuntime.q=[[kind,name,args],...]. */
var rt;
(function(){
var NATIVE={
'log':function(a){try{console.log.apply(console,a);}catch(e){}},
'log-addEventListener':function(){try{var o=EventTarget.prototype.addEventListener;EventTarget.prototype.addEventListener=function(t,l){try{console.log('addEventListener',String(t),typeof l==='function'?l.toString():String(l));}catch(e){}return o.apply(this,arguments);};}catch(e){}}
};
for(var k in ARGUS_NATIVES){if(Object.prototype.hasOwnProperty.call(ARGUS_NATIVES,k)&&!NATIVE[k])NATIVE[k]=ARGUS_NATIVES[k];}
var reported={},pend=[],tm=null;
function report(name){if(reported[name])return;reported[name]=1;pend.push('unsupported scriptlet '+name);if(!tm)tm=setTimeout(flush,0);}
function flush(){tm=null;var u=pend;pend=[];
try{fetch(base+'/__adblock__/cc',{method:'POST',headers:{'Content-Type':'application/json','X-Adblock-Token':cfg.t||''},body:JSON.stringify({url:pageUrl.slice(0,2000),unsupported:u}),credentials:'omit',cache:'no-store'}).catch(function(){});}catch(e){}}
/* The runtime is a plain object we or the proxy's own scripts made; markup (DOM clobbering) can make window.__argusRuntime an element or collection whose properties it controls. */
rt=self.__argusRuntime;if(Object.prototype.toString.call(rt)!=='[object Object]')rt={};
var q=Array.isArray(rt.q)?rt.q:[];
rt.run=function(kind,name,args){var f=Object.prototype.hasOwnProperty.call(NATIVE,name)?NATIVE[name]:null;if(!f){report(String(name).slice(0,64));return;}try{f(args||[]);}catch(e){}};
rt.q=[];self.__argusRuntime=rt;
for(var i=0;i<q.length;i++){try{rt.run(q[i][0],q[i][1],q[i][2]);}catch(e){}}
})();
/* Sites with a privileged userscript: drop any service worker already registered for this origin (a worker can read the page's bundles and GM traffic). New registrations are refused by the proxy. */
if(cfg.sw){try{if(navigator.serviceWorker&&navigator.serviceWorker.getRegistrations){navigator.serviceWorker.getRegistrations().then(function(rs){for(var i=0;i<rs.length;i++){try{rs[i].unregister();}catch(e){}}}).catch(function(){});}}catch(e){}}
var me=document.currentScript,nonce=nonce0!==undefined?nonce0:((me&&me.nonce)||'');
var tt=null;
try{if(window.trustedTypes&&trustedTypes.createPolicy){tt=trustedTypes.createPolicy('adblock-proxy',{createScriptURL:function(u){if(typeof u==='string'&&u.indexOf('/__adblock__/')===0)return u;throw new TypeError('adblock-proxy: refused');},createScript:function(s){return s;}});}}catch(e){}
function loadScript(path){var s=document.createElement('script');s.async=false;s.src=tt?tt.createScriptURL(path):path;if(nonce)s.setAttribute('nonce',nonce);(document.head||document.documentElement).appendChild(s);}
var sheet=null,styleEl=null;
function addCss(css){
try{if(!sheet&&window.CSSStyleSheet&&document.adoptedStyleSheets!==undefined){sheet=new CSSStyleSheet();document.adoptedStyleSheets=document.adoptedStyleSheets.concat([sheet]);sheet.__t='';}
if(sheet){sheet.__t+=css;sheet.replaceSync(sheet.__t);return;}}catch(e){sheet=null;}
if(!styleEl){styleEl=document.createElement('style');if(nonce)styleEl.setAttribute('nonce',nonce);(document.head||document.documentElement).appendChild(styleEl);}
styleEl.appendChild(document.createTextNode(css));}
function procedural(items){if(!items||!items.length)return;try{argusProceduralEngine(window,{addCss:addCss,nonce:nonce}).start(items);}catch(e){}}
/* A selector the browser rejects must cost only itself, not the batch it came in. */
function validSel(s){try{document.createDocumentFragment().querySelector(s);return true;}catch(e){return false;}}
function observer(){
var seen=new Set(),inflight=new Set(),applied=new Set(),timer=null,pending=false,fails=0,retry=null;
/* Largest request body the proxy takes is 64 KiB; stay under with room for the envelope. */
var LIMIT=60000;
function fresh(){var out=[],all=document.getElementsByTagName('*'),dup=new Set();
function add(t){if(!seen.has(t)&&!inflight.has(t)&&!dup.has(t)){dup.add(t);out.push(t);}}
for(var i=0;i<all.length;i++){var e=all[i];if(e.classList){for(var j=0;j<e.classList.length;j++)add('c:'+e.classList[j]);}if(e.id)add('i:'+e.id);}
return out;}
function batches(tokens){
var url=pageUrl.slice(0,2000),head=JSON.stringify({url:url,classes:[],ids:[]}).length,out=[],cur={c:[],i:[],t:[],n:head};
tokens.forEach(function(t){var v=t.slice(2),n=JSON.stringify(v).length+1;
if(cur.t.length&&cur.n+n>LIMIT){out.push(cur);cur={c:[],i:[],t:[],n:head};}
if(n+head>LIMIT)return;/* a single token that can never fit */
(t[0]==='c'?cur.c:cur.i).push(v);cur.t.push(t);cur.n+=n;});
if(cur.t.length)out.push(cur);return{list:out,url:url};}
function apply(sels){var add=[];sels.forEach(function(s){if(typeof s==='string'&&!applied.has(s)&&validSel(s)){applied.add(s);add.push(s);}});
if(add.length)addCss(add.join(',')+'{display:none!important}');}
function post(b,url){
b.t.forEach(function(t){inflight.add(t);});
return fetch(base+'/__adblock__/cc',{method:'POST',headers:{'Content-Type':'application/json','X-Adblock-Token':cfg.t||''},body:JSON.stringify({url:url,classes:b.c,ids:b.i}),credentials:'omit',cache:'no-store'})
.then(function(r){if(!r.ok)throw new Error('cc '+r.status);return r.json();})
.then(function(d){b.t.forEach(function(t){inflight.delete(t);seen.add(t);});fails=0;if(d&&d.selectors)apply(d.selectors);return true;})
.catch(function(){b.t.forEach(function(t){inflight.delete(t);});return false;});}
function request(){pending=false;
var t=fresh();if(!t.length)return;
var p=batches(t);
Promise.all(p.list.map(function(b){return post(b,p.url);})).then(function(rs){
if(rs.every(Boolean))return;
/* Nothing was marked seen for the failed batches: try them again, backing off, a few times. */
if(++fails>6||retry)return;
retry=setTimeout(function(){retry=null;request();},Math.min(30000,1000*Math.pow(2,fails-1)));});}
function schedule(){if(pending)return;pending=true;fails=fails>6?0:fails;timer=setTimeout(request,200);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',request);else request();
try{new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','id']});}catch(e){}}
/* Friendly frames: about:blank, srcdoc and blob: documents are never fetched through the proxy,
   so they get this boot (cosmetics, scriptlets, runtime) by reaching them through the parent. */
var doneDocs=new WeakSet();
var RTX="(function(){var r=self.__argusRuntime;return Object.prototype.toString.call(r)==='[object Object]'?r:(self.__argusRuntime={});})()";
function friendly(w){
try{var d=w.document;if(!d||doneDocs.has(d))return;
var h=String(w.location.href);
if(!(h==='about:blank'||h==='about:srcdoc'||h.indexOf('blob:')===0))return;
if(!d.documentElement)return;
doneDocs.add(d);
var fc={};for(var k in cfg){if(Object.prototype.hasOwnProperty.call(cfg,k)&&k!=='l'&&k!=='k'&&k!=='pn'&&k!=='sw')fc[k]=cfg[k];}
fc.u=pageUrl;
var st=document.getElementById('__adblock_cosmetic'),css=css0||(st?st.textContent:'');
var code='',fb=base||(/^https?:/.test(location.origin)?location.origin:'');
if(typeof rt.sl==='function')code+='(function(){var f=('+Function.prototype.toString.call(rt.sl)+');var r='+RTX+';r.sl=f;f();})();\n';
code+='('+argusBoot.toString()+')('+JSON.stringify(fc)+','+JSON.stringify(nonce)+','+JSON.stringify(fb)+','+JSON.stringify(css)+');\n';
if(typeof rt.xs==='string')code+='(function(){'+RTX+'.xs='+JSON.stringify(rt.xs)+';})();\n'+rt.xs+'\n';
var s=d.createElement('script');if(nonce)s.setAttribute('nonce',nonce);
s.textContent=tt&&tt.createScript?tt.createScript(code):code;
(d.head||d.documentElement).appendChild(s);s.remove();}catch(e){}}
rt.frame=friendly;
if(cfg.f){
try{var P=HTMLIFrameElement.prototype,gw=Object.getOwnPropertyDescriptor(P,'contentWindow'),gd=Object.getOwnPropertyDescriptor(P,'contentDocument');
/* Proxies keep toString / name / length native. */
Object.defineProperty(P,'contentWindow',{get:new Proxy(gw.get,{apply:function(t,th,a){var w=Reflect.apply(t,th,a);try{if(w)friendly(w);}catch(e){}return w;}}),configurable:true,enumerable:gw.enumerable});
Object.defineProperty(P,'contentDocument',{get:new Proxy(gd.get,{apply:function(t,th,a){var x=Reflect.apply(t,th,a);try{if(x&&x.defaultView)friendly(x.defaultView);}catch(e){}return x;}}),configurable:true,enumerable:gd.enumerable});}catch(e){}
/* A srcdoc / blob: frame replaces its initial document on load: do it again for the new one. */
try{document.addEventListener('load',function(e){var t=e.target;if(t&&t.tagName==='IFRAME'){try{friendly(gw.get.call(t));}catch(x){}}},true);}catch(e){}}
/* Frames: the plain hide rules the parent carries as a <style>; the page's own tag does it for the page. */
if(css0){try{addCss(css0);}catch(e){}}
if(cfg.o)observer();
procedural(cfg.p);
if(cfg.l){for(var i=0;i<cfg.l.length;i++)loadScript(cfg.l[i]);}
if(cfg.k){var K=cfg.k,pl=0;addEventListener('keydown',function(e){if(e.isTrusted&&e.altKey==!!K[0]&&e.ctrlKey==!!K[1]&&e.shiftKey==!!K[2]&&e.metaKey==!!K[3]&&e.code===K[4]){e.preventDefault();var t=window[Symbol.for('adblock.panel')];if(t)t();else if(!pl){pl=1;loadScript(cfg.pn);}}},true);}
