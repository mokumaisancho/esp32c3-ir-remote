#pragma once

#include <Arduino.h>

static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32-C3 IR Remote</title>
<style>
:root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#171717;background:#f5f5f5}
*{box-sizing:border-box} body{margin:0} main{max-width:760px;margin:auto;padding:18px}
h1{font-size:1.45rem;margin:0 0 4px} h2{font-size:1.05rem;margin:0 0 12px}
small,.muted{color:#666}.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:16px;margin:12px 0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.grow{flex:1 1 220px}
button,input{font:inherit;border-radius:8px;border:1px solid #bbb;padding:10px 12px}
button{background:#171717;color:#fff;border-color:#171717;cursor:pointer}
button.secondary{background:#fff;color:#171717} button.danger{background:#fff;color:#a00;border-color:#d99}
button:disabled{opacity:.45;cursor:default} input{background:#fff;width:100%}
#learnStatus{font-weight:650}.signal{border-top:1px solid #eee;padding:12px 0}.signal:first-child{border-top:0}
.badge{display:inline-block;padding:3px 8px;border:1px solid #ddd;border-radius:999px;font-size:.8rem;margin-right:6px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace} #raw{max-height:120px;overflow:auto;white-space:pre-wrap;word-break:break-all}
</style>
</head>
<body>
<main>
<h1>ESP32-C3 IR Remote</h1>
<div class="muted">Profile: ODELIC NRL-351N-JP / RX GPIO5 / TX GPIO7</div>

<section class="card">
<h2>接続状態</h2>
<div id="net">読み込み中…</div>
</section>

<section class="card">
<h2>5秒受信・記録</h2>
<div class="row">
<button id="learn">5秒受信・記録</button>
<button id="sendLast" class="secondary" disabled>今の信号を送信</button>
</div>
<p id="learnStatus">未受信</p>
<div id="lastMeta" class="muted"></div>
<pre id="raw"></pre>
<div class="row">
<div class="grow">
<input id="name" list="profileNames" maxlength="48" placeholder="識別名（例：全灯）">
<datalist id="profileNames">
<option value="全灯"><option value="消灯"><option value="常夜灯"><option value="シーン">
<option value="明るく"><option value="暗く"><option value="調色">
</datalist>
</div>
<button id="save" disabled>保存</button>
</div>
</section>

<section class="card">
<h2>保存済み信号</h2>
<div id="signals">読み込み中…</div>
</section>

<section class="card">
<h2>Wi-Fi設定</h2>
<p class="muted">初回は設定AP <code>ESP32C3-IR-Setup</code> に接続し、この画面から家庭内Wi-Fiを保存します。</p>
<div class="row">
<div class="grow"><input id="ssid" placeholder="SSID"></div>
<div class="grow"><input id="pass" type="password" placeholder="Password"></div>
<button id="wifi" class="secondary">保存して再起動</button>
</div>
</section>
</main>

<script>
const $=s=>document.querySelector(s);
async function api(path,opt={}){
  const r=await fetch(path,opt);
  const t=await r.text();
  let d; try{d=JSON.parse(t)}catch{d={ok:false,error:t}}
  if(!r.ok) throw new Error(d.error||d.message||t||r.status);
  return d;
}
function form(obj){const p=new URLSearchParams();Object.entries(obj).forEach(([k,v])=>p.set(k,v));return p}
async function refreshStatus(){
  const d=await api('/api/status');
  $('#net').innerHTML='<span class="badge">'+d.network_mode+'</span>'+d.ip+' · '+d.hostname;
  if(d.has_last){$('#sendLast').disabled=false}
}
async function refreshSignals(){
  const a=await api('/api/signals');
  if(!a.length){$('#signals').textContent='まだ保存されていません。';return}
  $('#signals').innerHTML='';
  a.forEach(s=>{
    const el=document.createElement('div'); el.className='signal';
    const top=document.createElement('div'); top.textContent=s.name; top.style.fontWeight='650';
    const meta=document.createElement('div'); meta.className='muted'; meta.textContent='#'+s.id+' · '+s.pulses+' pulses · '+s.duration_us+' µs';
    const row=document.createElement('div'); row.className='row'; row.style.marginTop='8px';
    const send=document.createElement('button'); send.textContent='送信'; send.onclick=async()=>{send.disabled=true;try{await api('/api/send',{method:'POST',body:form({id:s.id})})}finally{send.disabled=false}};
    const del=document.createElement('button'); del.textContent='削除'; del.className='danger'; del.onclick=async()=>{if(!confirm('「'+s.name+'」を削除しますか？'))return;await api('/api/delete',{method:'POST',body:form({id:s.id})});await refreshSignals()};
    row.append(send,del); el.append(top,meta,row); $('#signals').append(el);
  })
}
$('#learn').onclick=async()=>{
  const b=$('#learn'); b.disabled=true; $('#save').disabled=true; $('#sendLast').disabled=true; $('#raw').textContent='';
  const start=Date.now(); const timer=setInterval(()=>{const left=Math.max(0,5000-(Date.now()-start));$('#learnStatus').textContent='受信待機中… '+(left/1000).toFixed(1)+'秒'},100);
  try{
    const d=await api('/api/learn',{method:'POST'});
    $('#learnStatus').textContent=d.stored?'受信成功・自動保存済み #'+d.slot:'受信成功（保存できませんでした）';
    $('#lastMeta').textContent=d.pulses+' pulses · '+d.duration_us+' µs';
    $('#raw').textContent=d.raw.join(', ');
    $('#save').disabled=false; $('#sendLast').disabled=false; if(d.stored) await refreshSignals();
  }catch(e){$('#learnStatus').textContent='受信なし / '+e.message}
  finally{clearInterval(timer);b.disabled=false}
}
$('#save').onclick=async()=>{
  const name=$('#name').value.trim(); if(!name){alert('識別名を入力してください');return}
  await api('/api/save',{method:'POST',body:form({name})}); $('#name').value=''; await refreshSignals();
}
$('#sendLast').onclick=async()=>api('/api/send-last',{method:'POST'});
$('#wifi').onclick=async()=>{
  const ssid=$('#ssid').value.trim(); if(!ssid){alert('SSIDを入力してください');return}
  $('#wifi').disabled=true;
  try{await api('/api/wifi',{method:'POST',body:form({ssid,password:$('#pass').value})});alert('保存しました。ESP32-C3を再起動します。')}
  finally{$('#wifi').disabled=false}
}
Promise.all([refreshStatus(),refreshSignals()]).catch(e=>{$('#net').textContent='ERROR: '+e.message});
</script>
</body>
</html>
)HTML";
