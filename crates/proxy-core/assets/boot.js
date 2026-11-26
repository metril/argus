(function(){
if(window.__abBoot)return;window.__abBoot=1;
var cfg={};try{cfg=JSON.parse(document.getElementById('__ab_cfg').textContent)||{};}catch(e){}
/* Runtime for scriptlets/snippets that have no uBO equivalent: self.__argusRuntime.run(kind,name,args).
   Calls made before this script ran may be queued by the page injection in __argusRuntime.q=[[kind,name,args],...]. */
(function(){
var NATIVE={
'log':function(a){try{console.log.apply(console,a);}catch(e){}},
'log-addEventListener':function(){try{var o=EventTarget.prototype.addEventListener;EventTarget.prototype.addEventListener=function(t,l){try{console.log('addEventListener',String(t),typeof l==='function'?l.toString():String(l));}catch(e){}return o.apply(this,arguments);};}catch(e){}}
};
var reported={},pend=[],tm=null;
function report(name){if(reported[name])return;reported[name]=1;pend.push('unsupported scriptlet '+name);if(!tm)tm=setTimeout(flush,0);}
function flush(){tm=null;var u=pend;pend=[];
try{fetch('/__adblock__/cc',{method:'POST',headers:{'Content-Type':'application/json','X-Adblock-Token':cfg.t||''},body:JSON.stringify({url:location.href,unsupported:u}),credentials:'omit',cache:'no-store'}).catch(function(){});}catch(e){}}
var rt=self.__argusRuntime||{};var q=rt.q||[];
rt.run=function(kind,name,args){var f=Object.prototype.hasOwnProperty.call(NATIVE,name)?NATIVE[name]:null;if(!f){report(String(name).slice(0,64));return;}try{f(args||[]);}catch(e){}};
rt.q=[];self.__argusRuntime=rt;
for(var i=0;i<q.length;i++){try{rt.run(q[i][0],q[i][1],q[i][2]);}catch(e){}}
})();
/* Sites with a privileged userscript: drop any service worker already registered for this origin (a worker can read the page's bundles and GM traffic). New registrations are refused by the proxy. */
if(cfg.sw){try{if(navigator.serviceWorker&&navigator.serviceWorker.getRegistrations){navigator.serviceWorker.getRegistrations().then(function(rs){for(var i=0;i<rs.length;i++){try{rs[i].unregister();}catch(e){}}}).catch(function(){});}}catch(e){}}
var me=document.currentScript,nonce=(me&&me.nonce)||'';
var tt=null;
try{if(window.trustedTypes&&trustedTypes.createPolicy){tt=trustedTypes.createPolicy('adblock-proxy',{createScriptURL:function(u){if(typeof u==='string'&&u.indexOf('/__adblock__/')===0)return u;throw new TypeError('adblock-proxy: refused');}});}}catch(e){}
function loadScript(path){var s=document.createElement('script');s.async=false;s.src=tt?tt.createScriptURL(path):path;if(nonce)s.setAttribute('nonce',nonce);(document.head||document.documentElement).appendChild(s);}
var sheet=null,styleEl=null;
function addCss(css){
try{if(!sheet&&window.CSSStyleSheet&&document.adoptedStyleSheets!==undefined){sheet=new CSSStyleSheet();document.adoptedStyleSheets=document.adoptedStyleSheets.concat([sheet]);sheet.__t='';}
if(sheet){sheet.__t+=css;sheet.replaceSync(sheet.__t);return;}}catch(e){sheet=null;}
if(!styleEl){styleEl=document.createElement('style');if(nonce)styleEl.setAttribute('nonce',nonce);(document.head||document.documentElement).appendChild(styleEl);}
styleEl.appendChild(document.createTextNode(css));}
function procedural(items){if(!items||!items.length)return;try{argusProceduralEngine(window,{addCss:addCss,nonce:nonce}).start(items);}catch(e){}}
function observer(){
var seen=new Set(),applied=new Set(),timer=null,pending=false;
function collect(){var cls=new Set(),ids=new Set(),all=document.getElementsByTagName('*');
for(var i=0;i<all.length;i++){var e=all[i];if(e.classList){for(var j=0;j<e.classList.length;j++)cls.add(e.classList[j]);}if(e.id)ids.add(e.id);}
var nc=[],ni=[];cls.forEach(function(c){if(!seen.has('c:'+c)){seen.add('c:'+c);nc.push(c);}});ids.forEach(function(d){if(!seen.has('i:'+d)){seen.add('i:'+d);ni.push(d);}});return{classes:nc,ids:ni};}
function request(){pending=false;var t=collect();if(!t.classes.length&&!t.ids.length)return;
fetch('/__adblock__/cc',{method:'POST',headers:{'Content-Type':'application/json','X-Adblock-Token':cfg.t||''},body:JSON.stringify({url:location.href,classes:t.classes,ids:t.ids}),credentials:'omit',cache:'no-store'})
.then(function(r){return r.ok?r.json():null;}).then(function(d){if(!d||!d.selectors)return;var add='';d.selectors.forEach(function(s){if(!applied.has(s)){applied.add(s);add+=s+',';}});if(add){addCss(add.slice(0,-1)+'{display:none!important}');}}).catch(function(){});}
function schedule(){if(pending)return;pending=true;timer=setTimeout(request,200);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',request);else request();
try{new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','id']});}catch(e){}}
if(cfg.o)observer();
procedural(cfg.p);
if(cfg.l){for(var i=0;i<cfg.l.length;i++)loadScript(cfg.l[i]);}
if(cfg.k){var K=cfg.k,pl=0;addEventListener('keydown',function(e){if(e.isTrusted&&e.altKey==!!K[0]&&e.ctrlKey==!!K[1]&&e.shiftKey==!!K[2]&&e.metaKey==!!K[3]&&e.code===K[4]){e.preventDefault();var t=window[Symbol.for('adblock.panel')];if(t)t();else if(!pl){pl=1;loadScript(cfg.pn);}}},true);}
})();
