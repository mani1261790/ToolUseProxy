'use strict';
const $ = id => document.getElementById(id);
let selectedRevision = null;
const viewParams = new URLSearchParams(location.search);
let pinnedEvent = viewParams.get('id');
let currentEvent = null;
let lastGraph = '';
function navigation() {
  const params = new URLSearchParams(viewParams);
  params.delete('id');
  if (pinnedEvent) params.set('id', pinnedEvent);
  const suffix = params.size ? '?' + params : '';
  $('log-link').href = 'index.html' + suffix;
  $('graph-link').href = 'graph.html' + suffix;
  $('view-mode').textContent = pinnedEvent ? '選択した呼び出しの来歴' : '最新の呼び出しの来歴';
}
function pick(n) {
  pinnedEvent = n.event;
  select(n);
  navigation();
  history.replaceState(null, '', $('graph-link').href);
}

const ns = 'http://www.w3.org/2000/svg';
function el(tag, text) { const e = document.createElement(tag); if(text)e.textContent=text; return e; }
function svg(tag, attrs, text) { const e = document.createElementNS(ns,tag); for(const [k,v] of Object.entries(attrs))e.setAttribute(k,v); if(text)e.textContent=text;return e; }
function select(n) {
  selectedRevision = n.id;

  for(const g of $('graph').querySelectorAll('g[tabindex]'))g.setAttribute('aria-pressed',String(g.dataset.id===n.id));
  const stamp = n.time ? new Date(n.time.includes('T') ? n.time : n.time.replace(' ', 'T') + 'Z').toLocaleString('ja-JP') : '時刻未記録';
  const identity = el('p', `${stamp} · セッション: ${n.session}`);identity.className='hint identity';
  $('detail').replaceChildren(el('h2',n.tool || 'ToolCall'),identity);
  const analysis=el('div');analysis.className='decision';
  analysis.append(el('strong',n.complete?(n.provenance_scope==='selected_output'?'使用する出力の来歴を解析済み':'来歴解析済み'):'依存関係に未解析あり'),el('p',n.complete?(n.provenance_scope==='selected_output'?'後続の呼び出しが使う出力部分の由来を解析しました。操作全体の解析結果とは異なります。':'この呼び出しの依存関係を解析しました。'):'一部の依存関係は未解析です。検査済み安全を意味しません。'));
  $('detail').append(analysis,el('h3','関連する資源'));
  const list=el('ul');list.className='resource-list';
  for(const a of n.accesses){const item=el('li',a.path);item.append(el('span',`${a.mode==='write'?'書込み':'読取り'}${a.protected?' · 判定時の保護情報源':''}`));
    const versions=(n.versions||[]).filter(v=>v.path===a.path&&v.mode===a.mode);
    for(const v of versions)item.append(el('span',`観測した版: ${v.version.slice(0,16)}`));list.append(item);}
  $('detail').append(list);
  if(!n.accesses.length){const empty=el('p','資源へのアクセスは記録されていません。');empty.className='hint';$('detail').append(empty);}

}
function draw(data) {
  $('count').textContent=`${data.nodes.length}件`;
  $('status').textContent=data.nodes.length?'矢印: 依存元 → 利用先':'来歴グラフはまだありません';
  $('updated').textContent=`最終確認 ${new Date().toLocaleTimeString('ja-JP')}`;
  $('checks').replaceChildren();
  const held = (data.judgments||[]).find(j=>j.state!=='complete'||j.held);
  if(held){
    const message=held.state==='complete'?'再判定が完了しました。元の操作は自動実行されません。実行を要求すると、その時点の状態で再検査します。':`判定中・実行を保留しています。判定の試行: ${held.attempts}回。流出検出ではありません。`;
    const p=el('p',message);p.className='check';$('checks').append(p);
  }
  for(const c of data.checks){
    let message;
    if(c.action==='block')message=c.reason==='protected_content_match'?'保護内容との一致を検出しました。':'保護情報につながる来歴を検出しました。';
    else if(c.action==='unavailable')message='検査は未完了です。流出検出ではありません。';
    else if(c.action==='observed')message='操作後の記録です。実行前の許可判定とは別の記録です。';
    else message='検査結果: 許可。実行の有無はログで確認してください。';
    const p=el('p',message);p.className=`check ${c.action==='block'?'blocked':''}`;$('checks').append(p);
  }
  const nodes=[...data.nodes].reverse(), positions=new Map();
  // Ancestors appear above their consumers. Fan-in stays visible in alternating lanes.
  const depths=new Map();for(const n of nodes)depths.set(n.id,0);
  for(let i=0;i<nodes.length;i++){let changed=false;for(const e of data.edges){const d=(depths.get(e.source)||0)+1;if(d>(depths.get(e.target)||0)&&d<nodes.length){depths.set(e.target,d);changed=true;}}if(!changed)break;}
  const lanes=new Map();for(const n of nodes){const d=depths.get(n.id)||0;const lane=lanes.get(d)||0;lanes.set(d,lane+1);positions.set(n.id,{x:20+lane*300,y:20+d*125});}
  const width=Math.max(320,...[...lanes.values()].map(v=>v*300+20)),height=Math.max(180,(Math.max(0,...depths.values())+1)*125+20);
  const root=$('graph');root.replaceChildren();root.setAttribute('width',width);root.setAttribute('height',height);root.setAttribute('viewBox',`0 0 ${width} ${height}`);
  const defs=svg('defs',{}),marker=svg('marker',{id:'arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto'});marker.append(svg('polygon',{points:'0,0 10,5 0,10',fill:'#7e8c9b'}));defs.append(marker);root.append(defs);
  for(const e of data.edges){const a=positions.get(e.source),b=positions.get(e.target);root.append(svg('path',{d:`M ${a.x+140} ${a.y+85} C ${a.x+140} ${a.y+110}, ${b.x+140} ${b.y-25}, ${b.x+140} ${b.y}`,'marker-end':'url(#arrow)'}));}
  for(const n of nodes){const p=positions.get(n.id),g=svg('g',{tabindex:0,role:'button','aria-label':`${n.tool} セッション ${n.session}`,'aria-pressed':'false'});g.dataset.id=n.id;g.append(svg('rect',{x:p.x,y:p.y,width:280,height:85}),svg('text',{x:p.x+15,y:p.y+29},(n.tool||'ToolCall').slice(0,30)),svg('text',{x:p.x+15,y:p.y+53,class:'secondary'},n.accesses.length?`${n.accesses[0].mode==='write'?'書込み':'読取り'} · ${n.accesses[0].path}`.slice(0,28):`セッション ${String(n.session).slice(0,18)}`),svg('text',{x:p.x+15,y:p.y+73,class:'secondary'},n.accesses.some(a=>a.protected)?'保護情報源の読取り':n.complete?(n.provenance_scope==='selected_output'?'使用する出力の来歴を解析済み':'来歴解析済み'):'依存関係に未解析あり'));g.onclick=()=>pick(n);g.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(n);}};root.append(g);}
  $('note').textContent=(data.truncated?'表示上限に達しました。一部のノード・辺を省略しています。 ':'')+`解析ジョブ: ${(data.jobs||[]).map(j=>j.status).join(', ')||'記録なし'}。不足証拠の記録: ${(data.needs||[]).length}件。過去の判定版を表示します。現在の保護機能の稼働状態ではありません。`;
  const chosen=data.nodes.find(n=>n.id===selectedRevision)||data.nodes[0];
  if(chosen)select(chosen);
  else {$('detail').replaceChildren(el('h2','来歴グラフはまだありません'),el('p','この呼び出しの解析結果が記録されると、左側に表示されます。'));}
}
async function refresh() {
  const target = pinnedEvent;
  try {
    let id = target;
    if (!id) {
      const params = new URLSearchParams(viewParams); params.delete('id');
      const list = await fetch('api/events?' + params, {cache:'no-store'});
      if (!list.ok) throw Error();
      id = (await list.json()).calls[0]?.event_id || '';
    }
    const r = await fetch(`api/graph?id=${encodeURIComponent(id)}`, {cache:'no-store'});
    if (!r.ok) throw Error();
    const data = await r.json();
    if (target !== pinnedEvent) return;
    if (id !== currentEvent) { selectedRevision = null; currentEvent = id; lastGraph = ''; }
    const signature = JSON.stringify(data);
    if (signature !== lastGraph) { draw(data); lastGraph = signature; }
    navigation();
    $('connection').textContent = '● 接続済み';
    $('connection').className = 'online';
    $('updated').textContent = `最終確認 ${new Date().toLocaleTimeString('ja-JP')}`;
  } catch {
    $('connection').textContent = '再接続待ち';
    $('connection').className = 'offline';
  } finally { setTimeout(refresh, 1000); }
}
navigation(); refresh();
