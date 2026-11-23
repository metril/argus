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
function procedural(items){if(!items||!items.length)return;
var NAMES=['has-text','matches-css-before','matches-css-after','matches-css','matches-attr','matches-path','min-text-length','upward','xpath','-abp-contains','contains'];
function parseSel(sel){var ops=[],out='',n=sel.length,i=0;
while(i<n){if(sel[i]===':'){var matched=null;for(var k=0;k<NAMES.length;k++){var nm=NAMES[k];if(sel.substr(i+1,nm.length)===nm&&sel.charAt(i+1+nm.length)==='('){matched=nm;break;}}
if(matched){var start=i+1+matched.length+1,depth=1,j=start;while(j<n){var c=sel[j];if(c==='(')depth++;else if(c===')'){depth--;if(depth===0)break;}j++;}
ops.push({n:(matched==='-abp-contains'||matched==='contains')?'has-text':matched,a:sel.slice(start,j)});i=j+1;continue;}}
out+=sel[i];i++;}
return{css:out.trim(),ops:ops};}
function rx(s){if(s&&s.length>1&&s[0]==='/'){var i=s.lastIndexOf('/');if(i>0){try{return new RegExp(s.slice(1,i),s.slice(i+1));}catch(e){}}}return null;}
function applyOp(nodes,op){var nm=op.n,a=op.a,out=[];
for(var i=0;i<nodes.length;i++){var el=nodes[i];
if(nm==='has-text'){var re=rx(a),t=el.textContent||'';if(re?re.test(t):t.indexOf(a)!==-1)out.push(el);}
else if(nm==='min-text-length'){if((el.textContent||'').length>=parseInt(a,10))out.push(el);}
else if(nm==='matches-path'){var re=rx(a);if(re?re.test(location.pathname):location.pathname.indexOf(a)!==-1)out.push(el);}
else if(nm==='matches-css'||nm==='matches-css-before'||nm==='matches-css-after'){var p=nm==='matches-css'?null:(nm==='matches-css-before'?'::before':'::after');var ix=a.indexOf(':');if(ix>=0){var pr=a.slice(0,ix).trim(),v=a.slice(ix+1).trim();var cs=getComputedStyle(el,p);var ac=cs.getPropertyValue(pr)||'';var re=rx(v);if(re?re.test(ac):ac.trim()===v)out.push(el);}}
else if(nm==='matches-attr'){var m=a.match(/^([^=]+)(?:=([\s\S]*))?$/);if(m){var name=m[1].trim();if(el.hasAttribute(name)){if(m[2]===undefined)out.push(el);else{var v=el.getAttribute(name)||'';var re=rx(m[2]);if(re?re.test(v):v===m[2].replace(/^"|"$/g,''))out.push(el);}}}}
else if(nm==='upward'){var num=parseInt(a,10);if(!isNaN(num)&&String(num)===a.trim()){var e=el;while(num-->0&&e)e=e.parentElement;if(e)out.push(e);}else{try{var c=el.closest(a);if(c)out.push(c);}catch(e){}}}
else if(nm==='xpath'){try{var r=document.evaluate(a,el,null,XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null);for(var q=0;q<r.snapshotLength;q++){var nd=r.snapshotItem(q);if(nd.nodeType===1)out.push(nd);}}catch(e){}}
else out.push(el);}
return out.filter(function(v,ix){return out.indexOf(v)===ix;});}
function evalItem(it){var ps=parseSel(it.s),nodes;
try{nodes=ps.css?[].slice.call(document.querySelectorAll(ps.css)):[].slice.call(document.querySelectorAll('*'));}catch(e){return[];}
for(var i=0;i<ps.ops.length;i++){nodes=applyOp(nodes,ps.ops[i]);if(!nodes.length)break;}return nodes;}
function run(){for(var f=0;f<items.length;f++){var it=items[f],nodes;try{nodes=evalItem(it);}catch(e){continue;}
for(var i=0;i<nodes.length;i++){var el=nodes[i];try{
if(it.a==='remove')el.remove();
else if(it.a==='style')el.style.cssText+=';'+(it.g||'');
else if(it.a==='remove-attr')el.removeAttribute(it.g||'');
else if(it.a==='remove-class')el.classList.remove(it.g||'');
else el.style.setProperty('display','none','important');}catch(e){}}}}
var t=null;function sch(){if(t)clearTimeout(t);t=setTimeout(run,200);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run);else run();
try{new MutationObserver(sch).observe(document.documentElement,{childList:true,subtree:true,attributes:true});}catch(e){}}
function observer(){
var seen=new Set(),applied=new Set(),timer=null,pending=false;
function collect(){var cls=new Set(),ids=new Set(),all=document.getElementsByTagName('*');
for(var i=0;i<all.length;i++){var e=all[i];if(e.classList){for(var j=0;j<e.classList.length;j++)cls.add(e.classList[j]);}if(e.id)ids.add(e.id);}
var nc=[],ni=[];cls.forEach(function(c){if(!seen.has('c:'+c)){seen.add('c:'+c);nc.push(c);}});ids.forEach(function(d){if(!seen.has('i:'+d)){seen.add('i:'+d);ni.push(d);}});return{classes:nc,ids:ni};}
function request(){pending=false;var t=collect();if(!t.classes.length&&!t.ids.length)return;
fetch('/__adblock__/cc',{method:'POST',headers:{'Content-Type':'application/json','X-Adblock-Token':cfg.t||''},body:JSON.stringify({url:location.href,classes:t.classes,ids:t.ids}),credentials:'omit',cache:'no-store'})
.then(function(r){return r.ok?r.json():null;}).then(function(d){if(!d||!d.selectors)return;var add='';d.selectors.forEach(function(s){if(!applied.has(s)){applied.add(s);add+=s+',';}});if(add){addCss(add.slice(0,-1)+'{display:none!important}');}}).catch(function(){});}
function schedule(){if(pending)return;pending=true;if(timer)clearTimeout(timer);timer=setTimeout(request,200);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',request);else request();
try{new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','id']});}catch(e){}}
if(cfg.o)observer();
procedural(cfg.p);
if(cfg.l){for(var i=0;i<cfg.l.length;i++)loadScript(cfg.l[i]);}
if(cfg.k){var K=cfg.k,pl=0;addEventListener('keydown',function(e){if(e.isTrusted&&e.altKey==!!K[0]&&e.ctrlKey==!!K[1]&&e.shiftKey==!!K[2]&&e.metaKey==!!K[3]&&e.code===K[4]){e.preventDefault();var t=window[Symbol.for('adblock.panel')];if(t)t();else if(!pl){pl=1;loadScript(cfg.pn);}}},true);}
})();
