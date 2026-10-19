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
#learnStatus{font-weight:650}
#signals{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.signal{display:flex;align-items:center;gap:4px;flex-wrap:nowrap;min-width:0;border:1px solid #e6e6e6;border-radius:8px;padding:7px}
.signal .signal-name{font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:1}
.signal .signal-meta{font-size:.72rem;color:#666;white-space:nowrap}
.signal button{padding:6px 8px;font-size:.78rem;flex-shrink:0}
@media(max-width:690px){#signals{grid-template-columns:1fr}}

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
<div id="net" style="white-space:pre-line">読み込み中…</div>
<div id="rxReady" class="muted">RMT状態確認中…</div>
</section>

<section class="card">
<h2>5秒受信・記録</h2>
<div class="row">
<button id="learn">5秒受信・記録</button><label style="display:flex;align-items:center;gap:5px;font-size:.85rem"><input id="multi" type="checkbox" style="width:auto">長押し・複数フレームを学習</label>
<button id="sendLast" class="secondary" disabled>今の信号を送信</button><span id="txStatus" class="muted" role="status">送信未実施</span>
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
<h2>保存済み信号（LittleFS永続保存）</h2>
<div id="signals">読み込み中…</div>
</section>

<section class="card">
<h2>Wi-Fi設定</h2>
<p class="muted">設定AP <code>ESP32C3-IR-Setup</code>（<code>192.168.4.1</code>）は家庭内Wi-Fi接続後も復旧用として利用できます。接続先IPは上の接続状態欄に表示します。</p>
<p class="muted">固定パスワードの設定APが常時利用可能になるため、家庭内の信頼できる場所でのみ運用してください。</p>
<div class="row">
<div class="grow"><input id="ssid" placeholder="SSID"></div>
<div class="grow"><input id="pass" type="password" placeholder="Password"></div>
<button id="wifi" class="secondary">保存して接続</button>
</div>
<p id="wifiResult" class="muted">設定保存と接続成功は別々に確認します。</p>
</section>
</main>

<script>
const $=s=>document.querySelector(s);
async function api(path,opt={}){
  const r=await fetch(path,opt);
  const t=await r.text();
  let d; try{d=JSON.parse(t)}catch{d={ok:false,error:t}}
  if(!r.ok) throw new Error((d.error||d.message||t||r.status)+(typeof d.elapsed_ms==='number'?'（実測 '+d.elapsed_ms+'ms）':''));
  return d;
}
function form(obj){const p=new URLSearchParams();Object.entries(obj).forEach(([k,v])=>p.set(k,v));return p}
async function refreshStatus(){
  const d=await api('/api/status');
  const sta=d.sta_connected?'家庭内Wi-Fi: '+d.sta_ssid+'（IP '+d.sta_ip+'）':'家庭内Wi-Fi: 未接続';
  const ap=d.setup_ap_ready?'復旧用Wi-Fi: '+d.setup_ap_ssid+'（IP '+d.setup_ap_ip+'）':'復旧用Wi-Fi: 起動失敗';
  $('#net').textContent=sta+'\n'+ap+'\n接続状態: '+(d.wifi_phase||'UNKNOWN')+' (WiFi.status='+d.sta_status+')\nホスト名: '+d.hostname;
  if($('#wifiResult')) $('#wifiResult').textContent='自宅Wi-Fi: '+(d.wifi_phase||'UNKNOWN')+(d.sta_ip?' / '+d.sta_ip:'')+' / 再試行 '+d.sta_retry_count+'回';
  $('#rxReady').textContent='赤外線受信 GPIO'+d.rx_gpio+': '+(d.rmt_rx_ready?'準備完了':'初期化失敗');
  $('#learn').disabled=!d.rmt_rx_ready;
  // Reconcile action state from firmware, including after refresh/navigation.
  $('#save').disabled=!d.has_last;
  $('#sendLast').disabled=!d.has_last;
}
async function refreshSignals(){
  const a=await api('/api/signals');
  const list=$('#signals');
  if(!a.length){list.textContent='まだ保存されていません。';return}
  list.replaceChildren();
  a.forEach(s=>{
    const el=document.createElement('div'); el.className='signal';
    const name=document.createElement('span');name.className='signal-name';name.textContent='#'+s.id+' '+s.name;name.title=name.textContent;
    const send=document.createElement('button'); send.textContent='送信'; send.onclick=async()=>{send.disabled=true;setTxStatus('送信要求: '+s.name);try{const t=performance.now();const result=await api('/api/send',{method:'POST',body:form({id:s.id})});setTxStatus('RMT '+(result.result||'OK')+' / ESP処理 '+result.tx_duration_ms+'ms / HTTP往復 '+Math.round(performance.now()-t)+'ms / 試行#'+result.tx_attempt+' / 機器の受信は未確認: '+s.name)}catch(e){setTxStatus('送信失敗: '+e.message)}finally{send.disabled=false}};
    const del=document.createElement('button'); del.textContent='削除'; del.className='danger';
    del.onclick=async()=>{if(!confirm('「'+s.name+'」を削除しますか？'))return;del.disabled=true;try{await api('/api/delete',{method:'POST',body:form({id:s.id})});await refreshSignals()}catch(e){alert('削除失敗: '+e.message);del.disabled=false}};
    const meta=document.createElement('span');meta.className='signal-meta';meta.textContent=s.pulses+' pulses · '+s.duration_us+' µs'+(s.frames>1?' · '+s.frames+'F':'');meta.title=meta.textContent;
    el.append(name,send,del,meta);list.append(el);
  });
}
$('#learn').onclick=async()=>{
  const b=$('#learn'); b.disabled=true; $('#save').disabled=true; $('#sendLast').disabled=true; $('#raw').textContent='';
  const start=Date.now(); const timer=setInterval(()=>{const left=Math.max(0,5000-(Date.now()-start));$('#learnStatus').textContent='受信待機中… '+(left/1000).toFixed(1)+'秒'},100);
  try{
    const d=await api('/api/learn',{method:'POST',body:form({multi:$('#multi').checked?'1':'0'})});
    $('#learnStatus').textContent=d.stored?'受信成功・自動保存済み #'+d.slot:'受信成功（保存できませんでした）';
    // Unlock immediately after the successful API response; rendering/list refresh
    // must not prevent a saved capture from being transmitted.
    $('#save').disabled=false;
    $('#sendLast').disabled=false;
    $('#lastMeta').textContent=d.pulses+' pulses · '+(d.frames||1)+' frames · '+d.duration_us+' µs · '+d.elapsed_ms+'ms経過';
    $('#raw').textContent=Array.isArray(d.raw)?d.raw.join(', '):String(d.raw||'');
    if(d.stored) await refreshSignals();
  }catch(e){$('#learnStatus').textContent='受信なし / '+e.message}
  finally{clearInterval(timer);b.disabled=false}
}
$('#save').onclick=async()=>{
  const name=$('#name').value.trim(); if(!name){alert('識別名を入力してください');return}
  await api('/api/save',{method:'POST',body:form({name})}); $('#name').value=''; await refreshSignals();
}
function setTxStatus(message){$('#txStatus').textContent=new Date().toLocaleTimeString()+' '+message}
$('#sendLast').onclick=async()=>{const b=$('#sendLast');b.disabled=true;setTxStatus('直近信号を送信中');try{const t=performance.now();const result=await api('/api/send-last',{method:'POST'});setTxStatus('RMT '+(result.result||'OK')+' / ESP処理 '+result.tx_duration_ms+'ms / HTTP往復 '+Math.round(performance.now()-t)+'ms / 試行#'+result.tx_attempt+' / 機器の受信は未確認')}catch(e){setTxStatus('送信失敗: '+e.message)}finally{b.disabled=false}};
$('#wifi').onclick=async()=>{
  const ssid=$('#ssid').value.trim(); if(!ssid){alert('SSIDを入力してください');return}
  $('#wifi').disabled=true;
  try{const d=await api('/api/wifi',{method:'POST',body:form({ssid,password:$('#pass').value})});$('#wifiResult').textContent=d.saved?'保存済み・接続試行中（成功未確認）':'保存失敗'; await refreshStatus()}
  finally{$('#wifi').disabled=false}
}
Promise.all([refreshStatus(),refreshSignals()]).catch(e=>{$('#net').textContent='ERROR: '+e.message});
setInterval(()=>{if(document.visibilityState==='visible')refreshStatus().catch(e=>{$('#net').textContent='接続状態取得失敗: '+e.message})},10000);
</script>
</body>
</html>
)HTML";
