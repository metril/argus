/* Scriptlets that AdGuard lists use and uBlock Origin has no equivalent of, implemented for the
   page runtime (boot.js merges them into its NATIVE table). Each takes the rule's string
   arguments. Everything is defensive: a scriptlet must never throw into the page. */
var ARGUS_NATIVES=(function(){
var W=window;
function noop(){}
function esc(s){return String(s).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
/* uBO/AdGuard match argument: `/re/flags` or a plain substring; empty matches everything. */
function re(s){if(s===undefined||s==='')return /(?:)/;var m=/^\/(.+)\/([imsuy]*)$/.exec(s);if(m){try{return new RegExp(m[1],m[2]);}catch(e){}}return new RegExp(esc(s));}
function def(o,k,d){try{Object.defineProperty(o,k,d);}catch(e){}}
function dummy(o,k,v){def(o,k,{value:v,configurable:true,writable:true});}
/* Resolve `a.b.c` below the window: [owner, last key] (undefined owner while a link is missing). */
function chain(path){var p=String(path).split('.'),o=W;for(var i=0;i<p.length-1;i++){o=o==null?o:o[p[i]];}return[o,p[p.length-1]];}
function trap(path,onRead,onWrite){
var c=chain(path),o=c[0],k=c[1];if(!o)return;
var cur=o[k];
def(o,k,{configurable:true,get:function(){if(onRead)onRead();return cur;},set:function(v){if(onWrite)onWrite();cur=v;}});}
function waitFor(sel,cb){
try{var f=function(){var e=document.querySelector(sel);if(e){cb(e);return true;}return false;};
if(f())return;var mo=new MutationObserver(function(){if(f())mo.disconnect();});mo.observe(document.documentElement,{childList:true,subtree:true});}catch(e){}}

var N={
'noeval':function(){dummy(W,'eval',function(){});},
'no-floc':function(){try{delete Document.prototype.interestCohort;}catch(e){}dummy(Document.prototype,'interestCohort',undefined);},
'no-topics':function(){dummy(Document.prototype,'browsingTopics',function(){return Promise.resolve([]);});},
'no-protected-audience':function(){
['joinAdInterestGroup','leaveAdInterestGroup','updateAdInterestGroups','runAdAuction','clearOriginJoinedAdInterestGroups','createAuctionNonce','getInterestGroupAdAuctionData','canLoadAdAuctionFencedFrame','deprecatedReplaceInURN','deprecatedURNToURL'].forEach(function(n){
if(Navigator.prototype&&n in Navigator.prototype)dummy(Navigator.prototype,n,undefined);});
try{if(document.featurePolicy&&document.featurePolicy.allowsFeature){var o=document.featurePolicy.allowsFeature;dummy(Object.getPrototypeOf(document.featurePolicy),'allowsFeature',function(f){return /^(join-ad-interest-group|run-ad-auction)$/.test(f)?false:o.apply(this,arguments);});}}catch(e){}},
'log-eval':function(){var o=W.eval;dummy(W,'eval',function(s){try{console.log('eval('+String(s)+')');}catch(e){}return o.apply(this,arguments);});},
'dir-string':function(a){var n=0,max=parseInt(a[0],10)||1,o=console.dir;console.dir=function(x){if(n<max){n++;try{String(x);}catch(e){}}return o.apply(this,arguments);};},
'debug-on-property-read':function(a){if(a[0])trap(a[0],function(){debugger;});},
'debug-on-property-write':function(a){if(a[0])trap(a[0],null,function(){debugger;});},
'debug-current-inline-script':function(a){
if(!a[0])return;var me=document.currentScript;
trap(a[0],function(){var c=document.currentScript;if(c&&c!==me&&!c.src)debugger;});},
'set-popads-dummy':function(){['PopAds','popns'].forEach(function(n){try{delete W[n];}catch(e){}def(W,n,{configurable:true,get:function(){return{};},set:noop});});},
'prevent-popads-net':function(){['PopAds','popns'].forEach(function(n){def(W,n,{configurable:false,get:function(){return{};},set:noop});});},
'prevent-adfly':function(){
var enc;
def(W,'ysmm',{configurable:true,get:function(){return enc;},set:function(v){
enc=v;if(typeof v!=='string')return;
try{var a='',b='';for(var i=0;i<v.length;i++){if(i%2===0)a+=v[i];else b=v[i]+b;}
var arr=(a+b).split('');
for(var x=0;x<arr.length;x++){if(!isNaN(arr[x])){for(var y=x+1;y<arr.length;y++){if(!isNaN(arr[y])){var z=arr[x]^arr[y];if(z<10)arr[x]=z;x=y;y=arr.length;}}}}
var t=atob(arr.join(''));t=t.substring(16,t.length-16);
if(/^https?:\/\//i.test(t))setTimeout(function(){location.href=t;},0);}catch(e){}}});},
'prevent-fab-3.2.0':function(){
function Fab(){}
Fab.prototype.check=noop;Fab.prototype.clearEvent=noop;Fab.prototype.emitEvent=noop;Fab.prototype.setOption=noop;
Fab.prototype.on=function(detected,fn){if(!detected&&typeof fn==='function')try{fn();}catch(e){}return this;};
Fab.prototype.onDetected=function(){return this;};
Fab.prototype.onNotDetected=function(fn){return this.on(false,fn);};
Fab.prototype.options={set:noop,get:noop};
var inst=new Fab();
['FuckAdBlock','BlockAdBlock'].forEach(function(n){def(W,n,{configurable:true,value:Fab});});
['fuckAdBlock','blockAdBlock'].forEach(function(n){def(W,n,{configurable:true,value:inst});});},
'prevent-element-src-loading':function(a){
var tag=String(a[0]||'').toLowerCase(),m=re(a[1]);
var cls={script:W.HTMLScriptElement,img:W.HTMLImageElement,iframe:W.HTMLIFrameElement,link:W.HTMLLinkElement}[tag];
if(!cls)return;
var attr=tag==='link'?'href':'src';
var D={script:'data:text/javascript;base64,KCk9Pnt9',img:'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',iframe:'data:text/html;base64,PGh0bWw+PC9odG1sPg==',link:'data:text/css;base64,LyoqLw=='}[tag];
var bad=function(v){return typeof v==='string'&&v.indexOf('data:')!==0&&m.test(v);};
var sa=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){
try{if(this.localName===tag&&String(n).toLowerCase()===attr&&bad(String(v)))return sa.call(this,n,D);}catch(e){}
return sa.apply(this,arguments);};
var d=Object.getOwnPropertyDescriptor(cls.prototype,attr);
if(d&&d.set)def(cls.prototype,attr,{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){d.set.call(this,bad(String(v))?D:v);}});},
'prevent-textContent':function(a){
var sel=a[0]||'',p=re(a[1]);
var d=Object.getOwnPropertyDescriptor(Node.prototype,'textContent');
if(!d||!d.set)return;
def(Node.prototype,'textContent',{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){
try{if((!sel||(this.matches&&this.matches(sel)))&&p.test(String(v)))return;}catch(e){}
d.set.call(this,v);}});},
'hide-in-shadow-dom':function(a){inShadow(a,false);},
'remove-in-shadow-dom':function(a){inShadow(a,true);},
'metrika-yandex-tag':function(){yandex(false);},
'metrika-yandex-archive':function(){yandex(true);},
'google-ima3':function(){ima3();},
'trusted-create-element':function(a){
var parentSel=a[0],tagName=a[1];if(!parentSel||!tagName)return;
var attrs=[],raw=a[2]||'';
if(raw.indexOf('=')>=0){raw.replace(/([^\s=]+)=(?:"([^"]*)"|'([^']*)'|(\S*))/g,function(_,k,v1,v2,v3){attrs.push([k,v1!==undefined?v1:v2!==undefined?v2:v3]);return'';});}
else if(raw){attrs.push([raw,a[3]===undefined?'':a[3]]);}
var text=raw.indexOf('=')>=0?a[3]:a[4],delay=parseInt(raw.indexOf('=')>=0?a[4]:a[5],10)||0;
waitFor(parentSel,function(p){
try{var e=document.createElement(tagName);
attrs.forEach(function(kv){try{e.setAttribute(kv[0],kv[1]);}catch(x){}});
if(text)e.textContent=text;
p.appendChild(e);
if(delay>0)setTimeout(function(){try{e.remove();}catch(x){}},delay);}catch(x){}});},
'trusted-dispatch-event':function(a){
if(!a[0])return;var init={bubbles:true};
try{if(a[1])Object.assign(init,JSON.parse(a[1]));}catch(e){}
var go=function(){try{document.dispatchEvent(new CustomEvent(a[0],init));}catch(e){}};
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',go,{once:true});else go();}
};

function inShadow(a,remove){
var sel=a[0],base=a[1]||'';if(!sel)return;
function sweep(r){try{
if(base&&!(r.host&&r.host.matches&&r.host.matches(base)))return;
var l=r.querySelectorAll(sel);
for(var i=0;i<l.length;i++){if(remove)l[i].remove();else l[i].style.setProperty('display','none','important');}}catch(e){}}
function track(r){sweep(r);try{new MutationObserver(function(){sweep(r);}).observe(r,{childList:true,subtree:true,attributes:true});}catch(e){}}
try{var o=Element.prototype.attachShadow;
Element.prototype.attachShadow=function(){var r=o.apply(this,arguments);track(r);return r;};}catch(e){}
function scan(){try{var all=document.querySelectorAll('*');for(var i=0;i<all.length;i++){if(all[i].shadowRoot)track(all[i].shadowRoot);}}catch(e){}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',scan,{once:true});else scan();}

function yandex(archive){
var calls=function(args){for(var i=0;i<args.length;i++){if(typeof args[i]==='function'){try{args[i]();}catch(e){}}}};
function Metrika(){}
['addFileExtension','extLink','file','getClientID','hit','notBounce','params','replacePhones','setUserID','userParams','destruct','clickmap','trackLinks','accurateTrackBounce'].forEach(function(n){Metrika.prototype[n]=noop;});
Metrika.prototype.reachGoal=function(g,p,cb,ctx){if(typeof p==='function'){ctx=cb;cb=p;}if(typeof cb==='function'){try{cb.call(ctx);}catch(e){}}};
W.Ya=W.Ya||{};try{W.Ya.Metrika=Metrika;W.Ya.Metrika2=Metrika;}catch(e){}
var ym=function(id,m){var r=[].slice.call(arguments,2);if(m==='reachGoal'||m==='hit'){calls(r);}};
def(W,'ym',{configurable:true,writable:true,value:ym});
def(W,'yaCounter',{configurable:true,writable:true,value:new Metrika()});
if(archive){var cbs=W.yandex_metrika_callbacks;if(cbs&&cbs.length){for(var i=0;i<cbs.length;i++){try{cbs[i]();}catch(e){}}}
def(W,'yandex_metrika_callbacks',{configurable:true,writable:true,value:{push:function(f){try{f();}catch(e){}}}});}}

function ima3(){
function Target(){var l={};this.addEventListener=function(t,f){(l[t]=l[t]||[]).push(f);};
this.removeEventListener=function(t,f){l[t]=(l[t]||[]).filter(function(x){return x!==f;});};
this.dispatch=function(t,e){(l[t]||[]).slice().forEach(function(f){try{f(e);}catch(x){}});};}
var T={AD_ERROR:'adError',ALL_ADS_COMPLETED:'allAdsCompleted',CONTENT_PAUSE_REQUESTED:'contentPauseRequested',CONTENT_RESUME_REQUESTED:'contentResumeRequested',LOADED:'loaded',STARTED:'started',COMPLETE:'complete',SKIPPED:'skipped',USER_CLOSE:'userClose'};
function Ev(type,mgr){this.type=type;this.getAd=function(){return null;};this.getAdData=function(){return{};};this.getAdsManager=function(){return mgr;};this.getUserRequestContext=function(){return null;};}
function Mgr(){Target.call(this);var s=this;
['init','destroy','pause','resume','resize','skip','stop','collapse','expand','setVolume','focus','updateAdsRenderingSettings','clicked'].forEach(function(n){s[n]=noop;});
this.start=function(){setTimeout(function(){s.dispatch(T.CONTENT_RESUME_REQUESTED,new Ev(T.CONTENT_RESUME_REQUESTED,s));s.dispatch(T.ALL_ADS_COMPLETED,new Ev(T.ALL_ADS_COMPLETED,s));},0);};
this.getVolume=function(){return 1;};this.getRemainingTime=function(){return 0;};this.getAdSkippableState=function(){return false;};
this.getCuePoints=function(){return[];};this.isCustomPlaybackUsed=function(){return false;};this.isCustomClickTrackingUsed=function(){return false;};}
function Loader(){Target.call(this);var s=this,m=new Mgr();
this.requestAds=function(){setTimeout(function(){var e=new Ev('adsManagerLoaded',m);e.getAdsManager=function(){return m;};s.dispatch('adsManagerLoaded',e);},0);};
this.contentComplete=noop;this.destroy=noop;this.getSettings=function(){return ImaSettings;};this.getVersion=function(){return'3.0';};}
var ImaSettings={setLocale:noop,setVpaidMode:noop,setAutoPlayAdBreaks:noop,setPlayerType:noop,setPlayerVersion:noop,setPpid:noop,setNumRedirects:noop,setDisableCustomPlaybackForIOS10Plus:noop,getDisableCustomPlaybackForIOS10Plus:function(){return false;}};
function Container(){this.initialize=noop;this.destroy=noop;}
function Request(){}
W.google=W.google||{};
try{W.google.ima={VERSION:'3.0',AdsLoader:Loader,AdDisplayContainer:Container,AdsRequest:Request,AdsRenderingSettings:function(){},
AdsManagerLoadedEvent:{Type:{ADS_MANAGER_LOADED:'adsManagerLoaded'}},AdEvent:{Type:T},AdErrorEvent:{Type:{AD_ERROR:'adError'}},
ImaSdkSettings:Object.assign(function(){},{VpaidMode:{DISABLED:0,ENABLED:1,INSECURE:2}}),settings:ImaSettings,
ViewMode:{NORMAL:'normal',FULLSCREEN:'fullscreen'},UiElements:{AD_ATTRIBUTION:'adAttribution',COUNTDOWN:'countdown'},
AdError:function(){},OmidAccessMode:{},CompanionAdSelectionSettings:function(){}};}catch(e){}}

return N;
})();
