'use strict';
const $ = (id) => document.getElementById(id);
let selected = null;
let listJSON = '';
let detailJSON = '';
function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
async function get(path) {
  const response = await fetch(path, {cache: 'no-store'});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '接続できません');
  return data;
}
function callKey(call) {
  return JSON.stringify(call.session_id && call.tool_use_id ? [call.workspace_id, call.session_id, call.tool_use_id] : [call.event_id]);
}
function choose(call) {
  selected = call;
  detailJSON = '';
  listJSON = '';
}
function renderCalls(calls) {
  const signature = JSON.stringify([calls, selected?.event_id]);
  if (signature === listJSON) return;
  listJSON = signature;
  $('calls').replaceChildren();
  $('count').textContent = calls.length;
  if (!calls.length) $('calls').append(node('p', 'まだToolCallの記録がありません。', 'empty'));
  for (const call of calls) {
    const button = node('button', undefined, 'call');
    button.classList.toggle('selected', call.event_id === selected?.event_id);
    button.setAttribute('aria-pressed', String(call.event_id === selected?.event_id));
    button.append(node('strong', call.tool_name), node('time', call.recorded_at),
      node('span', call.blocked ? '■ ブロック判定' : [...new Set(call.phases)].reverse().join(' → '), 'hint'));
    button.onclick = () => { $('follow').checked = false; choose(call); renderCalls(calls); };
    $('calls').append(button);
  }
}
function renderDetail(data) {
  const signature = JSON.stringify([selected?.event_id, data]);
  if (signature === detailJSON) return;
  detailJSON = signature;
  $('title').textContent = selected.tool_name;
  $('identity').textContent = `Call: ${selected.tool_use_id || '未記録'} · Session: ${selected.session_id || '未記録'}`;
  $('decisions').replaceChildren();
  if (!data.decisions.length) $('decisions').append(node('p', '判定の記録なし', 'hint'));
  for (const d of data.decisions) {
    const box = node('div', undefined, d.action === 'block' ? 'decision blocked' : 'decision');
    box.append(node('strong', d.action === 'block' ? 'ToolUseProxy: ブロック判定' : `ToolUseProxy: ${d.action}`),
      node('p', d.user_message || d.reason), node('small', `${d.hook_event || 'Hook未記録'} · ${d.created_at}`));
    $('decisions').append(box);
  }
  $('io').replaceChildren();
  for (const [label, key] of [['入力', 'tool_input'], ['出力', 'tool_response']]) {
    const event = [...data.events].reverse().find(item => Object.hasOwn(item.payload, key));
    const section = node('article');
    section.append(node('h3', label), node('pre', event ? JSON.stringify(event.payload[key], null, 2) : '未記録'));
    $('io').append(section);
  }
  const raw = node('details');
  raw.append(node('summary', `保存されたイベント ${data.events.length} 件`));
  for (const event of data.events) {
    raw.append(node('h3', `${event.phase} · ${event.recorded_at}`));
    if (event.truncated) raw.append(node('p', '大きな記録のため先頭128K文字のみ表示しています。', 'hint'));
    raw.append(node('pre', JSON.stringify(event.payload, null, 2)));
  }
  if (data.events.some(event => event.truncated)) $('io').append(node('p', 'サイズ制限によりI/Oを抽出できない記録があります。下の保存イベントを確認してください。', 'hint'));
  $('io').append(raw);
  if (!data.events.length) $('io').append(node('p', 'この記録はDBにありません。', 'empty'));
}
async function refresh() {
  try {
    const data = await get('api/events');
    $('database').textContent = data.database;
    if (data.calls.length && (!selected || ($('follow').checked && selected.event_id !== data.calls[0].event_id))) choose(data.calls[0]);
    if (selected) selected = data.calls.find(call => callKey(call) === callKey(selected)) || selected;
    renderCalls(data.calls);
    if (selected) renderDetail(await get(`api/detail?id=${encodeURIComponent(selected.event_id)}`));
    $('connection').textContent = '● 接続中 · 自動更新';
    $('connection').className = 'online';
    $('updated').textContent = `最終確認 ${new Date().toLocaleTimeString('ja-JP')}`;
  } catch (error) {
    $('connection').textContent = `再接続待ち · ${error.message}`;
    $('connection').className = 'offline';
  } finally { setTimeout(refresh, 1000); }
}
refresh();
