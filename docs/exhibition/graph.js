'use strict';
const $ = id => document.getElementById(id);
const ns = 'http://www.w3.org/2000/svg';
function el(tag, text) { const e = document.createElement(tag); if(text)e.textContent=text; return e; }
function svg(tag, attrs, text) { const e = document.createElementNS(ns,tag); for(const [k,v] of Object.entries(attrs))e.setAttribute(k,v); if(text)e.textContent=text;return e; }
function select(n) {
  for(const g of $('graph').querySelectorAll('g[tabindex]'))g.setAttribute('aria-pressed',String(g.dataset.id===n.id));
  $('detail').replaceChildren(el('h2',n.tool || 'ToolCall'),el('p',`セッション: ${n.session} · ${n.time}`));
  $('detail').append(el('p',n.complete?'この呼び出しの来歴解析は完了しています。':'一部の依存関係は未解析です。検査済み安全を意味しません。'));
  const list=el('ul');for(const a of n.accesses)list.append(el('li',`${a.mode==='write'?'書込み':'読取り'}: ${a.path}${a.protected?'（判定時の保護情報源）':''}`));
  $('detail').append(list);
  for(const v of n.versions||[]) $('detail').append(el('p',`観測した資源版: ${v.path} · ${v.version.slice(0,16)}`));
}
function draw(data) {
  $('status').textContent=data.nodes.length?'選択した呼び出しへつながる来歴':'来歴グラフはまだありません';
  $('checks').replaceChildren();
  for(const c of data.checks){const p=el('p',c.action==='block'?(c.reason==='protected_content_match'?'保護内容との一致で停止。グラフの有無とは独立した判定です。':'保護情報につながる来歴を検出し、停止しました。'):c.action==='unavailable'?'検査は未完了です。流出検出ではありません。':'この操作の判定は通過です。');p.className=`check ${c.action==='block'?'blocked':''}`;$('checks').append(p);}
  const nodes=[...data.nodes].reverse(), positions=new Map();
  // Ancestors appear above their consumers. Fan-in stays visible in alternating lanes.
  const depths=new Map();for(const n of nodes)depths.set(n.id,0);
  for(let i=0;i<nodes.length;i++){let changed=false;for(const e of data.edges){const d=(depths.get(e.source)||0)+1;if(d>(depths.get(e.target)||0)&&d<nodes.length){depths.set(e.target,d);changed=true;}}if(!changed)break;}
  const lanes=new Map();for(const n of nodes){const d=depths.get(n.id)||0;const lane=lanes.get(d)||0;lanes.set(d,lane+1);positions.set(n.id,{x:40+lane*320,y:30+d*135});}
  const width=Math.max(720,...[...lanes.values()].map(v=>v*320+60)),height=Math.max(180,(Math.max(0,...depths.values())+1)*135+35);
  const root=$('graph');root.replaceChildren();root.setAttribute('width',width);root.setAttribute('height',height);root.setAttribute('viewBox',`0 0 ${width} ${height}`);
  const defs=svg('defs',{}),marker=svg('marker',{id:'arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto'});marker.append(svg('polygon',{points:'0,0 10,5 0,10',fill:'#7e8c9b'}));defs.append(marker);root.append(defs);
  for(const e of data.edges){const a=positions.get(e.source),b=positions.get(e.target);root.append(svg('path',{d:`M ${a.x+140} ${a.y+85} C ${a.x+140} ${a.y+110}, ${b.x+140} ${b.y-25}, ${b.x+140} ${b.y}`,'marker-end':'url(#arrow)'}));}
  for(const n of nodes){const p=positions.get(n.id),g=svg('g',{tabindex:0,role:'button','aria-label':`${n.tool} セッション ${n.session}`,'aria-pressed':'false'});g.dataset.id=n.id;g.append(svg('rect',{x:p.x,y:p.y,width:280,height:85}),svg('text',{x:p.x+15,y:p.y+29},(n.tool||'ToolCall').slice(0,30)),svg('text',{x:p.x+15,y:p.y+53,class:'secondary'},`セッション ${String(n.session).slice(0,20)}`),svg('text',{x:p.x+15,y:p.y+73,class:'secondary'},n.accesses.some(a=>a.protected)?'保護情報源の読取り':n.complete?'来歴解析済み':'依存関係に未解析あり'));g.onclick=()=>select(n);g.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();select(n);}};root.append(g);}
  $('note').textContent=(data.truncated?'表示上限に達しました。一部のノード・辺を省略しています。 ':'')+`解析ジョブ: ${(data.jobs||[]).map(j=>j.status).join(', ')||'記録なし'}。不足証拠の記録: ${(data.needs||[]).length}件。過去の判定版を表示します。現在の保護機能の稼働状態ではありません。`;
  if(data.nodes.length)select(data.nodes[0]);
}
async function refresh(){try{const id=new URLSearchParams(location.search).get('id')||'';const r=await fetch(`api/graph?id=${encodeURIComponent(id)}`,{cache:'no-store'});if(!r.ok)throw Error();draw(await r.json());}catch{$('status').textContent='ログとの接続が切れました。保護状態はこの画面では確認できません。';}}
$('refresh').onclick=refresh;refresh();
