// Secure bootloader web dashboard, served by the ESP32
#pragma once
static const char WEB_PAGE[] = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Bootloader</title>
<style>
:root{--bg:#f2f1ed;--panel:#fff;--line:#dcd9d1;--ink:#1e1f22;--mut:#666a70;--acc:#3557a6;--ok:#2d7a4f;--bad:#b3362a;--warn:#b26f00;--btn:#f7f6f2;--chip:#eceae4;color-scheme:light}
:root[data-theme="dark"]{--bg:#121315;--panel:#1b1c20;--line:#2c2e33;--ink:#e7e8ea;--mut:#9396a0;--acc:#7c9cf0;--ok:#5cc489;--bad:#ef6b5e;--warn:#f0a531;--btn:#222428;--chip:#26282d;color-scheme:dark}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121315;--panel:#1b1c20;--line:#2c2e33;--ink:#e7e8ea;--mut:#9396a0;--acc:#7c9cf0;--ok:#5cc489;--bad:#ef6b5e;--warn:#f0a531;--btn:#222428;--chip:#26282d;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
main{max-width:1040px;margin:0 auto;display:grid;gap:14px}
header{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}h1{font-size:20px;margin:0}
h2{font-size:12px;margin:0 0 10px;color:var(--mut);text-transform:uppercase;letter-spacing:.07em;font-weight:600}
.mono{font-family:ui-monospace,"SFMono-Regular",Consolas,monospace;font-variant-numeric:tabular-nums}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}
.top{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) minmax(0,1fr);gap:14px}@media(max-width:820px){.top{grid-template-columns:1fr}}
.big{font-size:24px;font-weight:650}.sub{color:var(--mut);font-size:13px}
.led{display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--line);margin-right:8px;vertical-align:middle;transition:background .05s}
.led.on{background:var(--ok);box-shadow:0 0 10px var(--ok)}
.chip{display:inline-block;font-size:12px;font-weight:600;padding:2px 9px;border-radius:99px;background:var(--chip);color:var(--mut);margin:2px 4px 2px 0}
.chip.ok{background:var(--ok);color:var(--panel)}.chip.bad{background:var(--bad);color:#fff}.chip.warn{background:var(--warn);color:var(--panel)}.chip.acc{background:var(--acc);color:var(--panel)}
.slot.active{border-color:var(--ok)}.slot.pending{border-color:var(--warn)}
.cols{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}@media(max-width:820px){.cols{grid-template-columns:1fr}}
.scen{display:grid;gap:8px}
.scen button{display:flex;justify-content:space-between;gap:10px;text-align:left;width:100%}
.scen small{color:var(--mut)}
button{font:inherit;background:var(--btn);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:8px 12px;cursor:pointer}
button:hover:not(:disabled){border-color:var(--acc)}button:disabled{opacity:.5;cursor:not-allowed}button:focus-visible{outline:2px solid var(--acc)}
button.danger{color:var(--bad)}
.prog{height:8px;background:var(--chip);border-radius:99px;overflow:hidden;margin:8px 0 4px}.prog span{display:block;height:100%;width:0;background:var(--acc)}
#banner{display:none;padding:12px 14px;border-radius:10px;font-weight:600}
ol{list-style:none;margin:0;padding:0;font-size:12.5px;max-height:330px;overflow:auto}ol li{padding:4px 0;border-bottom:1px solid var(--line)}ol span{color:var(--mut);margin-right:8px}
</style></head><body><main>
<header><h1>Secure Bootloader</h1>
<span style="display:flex;gap:10px;align-items:center"><span class="mono" id="conn" style="color:var(--mut)">connecting…</span><button id="theme" aria-label="Toggle theme">◐</button></span></header>
<div id="banner"></div>

<section class="top">
 <div class="panel"><h2>Running firmware</h2>
  <div class="big"><span class="led" id="led"></span><span id="appname">–</span></div>
  <div class="sub" id="appmsg"></div>
  <div style="margin-top:10px" id="bootchips"></div>
  <div class="sub mono" style="margin-top:8px" id="verify"></div>
 </div>
 <div class="panel slot" id="slotA"></div>
 <div class="panel slot" id="slotB"></div>
</section>

<section class="cols">
 <div class="panel"><h2>Update scenarios</h2>
  <div class="scen">
   <button data-c="1"><span>Install v2.0</span><small>signed, valid</small></button>
   <button data-c="2"><span>Install v3.0</span><small>signed but buggy → rollback</small></button>
   <button data-c="3"><span>Tampered image</span><small>modified content + recomputed hash</small></button>
   <button data-c="4"><span>Signed with another key</span><small>attacker's firmware</small></button>
   <button data-c="5"><span>Downgrade to v1.0</span><small>old version, known vulnerabilities</small></button>
   <button data-c="6"><span>Power cut</span><small>while installing v2.0</small></button>
  </div>
  <div class="prog" id="progw" hidden><span id="prog"></span></div>
  <div class="sub" id="status"></div>
  <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap"><button data-c="r">Reboot</button><button class="danger" id="factory">Factory reset</button></div>
 </div>
 <div class="panel"><h2>Bootloader log</h2><ol class="mono" id="log"></ol></div>
</section>
</main><script>
const $=id=>document.getElementById(id);
(function(){const r=document.documentElement;let t=null;try{t=localStorage.getItem('theme')}catch(e){}if(t)r.dataset.theme=t;
 const cur=()=>r.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
 const lab=()=>{$('theme').textContent=cur()=='dark'?'☀':'☾'};
 $('theme').onclick=()=>{r.dataset.theme=cur()=='dark'?'light':'dark';try{localStorage.setItem('theme',r.dataset.theme)}catch(e){}lab()};lab()})();
let blink=500,lastUp=0,factoryArm=0;
async function cmd(c){try{await fetch('/api/cmd?c='+c)}catch(e){}}
document.querySelectorAll('button[data-c]').forEach(b=>b.onclick=()=>cmd(b.dataset.c));
$('factory').onclick=()=>{if(Date.now()-factoryArm<3000){cmd('e');factoryArm=0;$('factory').textContent='Factory reset'}
 else{factoryArm=Date.now();$('factory').textContent='Confirm: erase everything?';setTimeout(()=>{if(factoryArm){factoryArm=0;$('factory').textContent='Factory reset'}},3000)}};
(function tick(){$('led').classList.toggle('on');setTimeout(tick,Math.max(60,blink))})();
const chip=(t,c)=>'<span class="chip '+(c||'')+'">'+t+'</span>';
function slot(el,s,id){el.className='panel slot'+(s.active?' active':s.pending?' pending':'');
 el.innerHTML='<h2>Slot '+id+'</h2>'+(s.ok?'<div class="big">'+s.name+'</div><div class="sub mono">version '+s.ver+'</div><div style="margin-top:8px">'+chip('signature OK','ok')+(s.active?chip('active','acc'):'')+(s.pending?chip('on trial','warn'):'')+'</div>'
  :'<div class="big" style="color:var(--mut)">'+(s.status=='empty slot'?'empty':'invalid')+'</div><div class="sub">'+s.status+'</div>')}
async function refresh(){try{
 const s=await (await fetch('/api/state')).json();
 if(s.uptime<lastUp){$('banner').style.display='block';$('banner').style.background='var(--chip)';$('banner').textContent='The board just rebooted: the bootloader verified the signature and selected slot '+s.boot.slot+'.';setTimeout(()=>$('banner').style.display='none',6000)}
 lastUp=s.uptime;$('conn').textContent='ESP32 online';
 blink=s.app.blink;$('appname').textContent=s.app.name;$('appmsg').textContent=s.app.msg+' · LED every '+s.app.blink+' ms';
 $('bootchips').innerHTML=chip('slot '+s.boot.slot,'acc')+(s.boot.trial?chip('trial boot '+s.boot.tries+'/'+s.boot.max,'warn'):chip('confirmed version','ok'))+(s.boot.rolledBack?chip('rolled back','bad'):'')+chip('min. version v'+s.minVersion);
 $('verify').textContent='SHA-256 + ECDSA P-256 signature verified in '+s.boot.verifyMs+' ms at boot';
 slot($('slotA'),s.slots[0],'A');slot($('slotB'),s.slots[1],'B');
 $('progw').hidden=s.progress<0;$('prog').style.width=Math.max(0,s.progress)+'%';$('status').textContent=s.status;$('status').style.color=/REJECT|CRASH/.test(s.status)?'var(--bad)':/OK/.test(s.status)?'var(--ok)':'var(--mut)';
 document.querySelectorAll('button[data-c]').forEach(b=>b.disabled=!!s.busy);
 $('log').innerHTML=s.log.map(l=>'<li><span>'+(l.t/1000).toFixed(1)+' s</span>'+l.m+'</li>').join('');
}catch(e){$('conn').textContent='board rebooting…'}}
refresh();setInterval(refresh,400);
</script></body></html>)HTML";
