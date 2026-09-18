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
function readable(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}
function timeLabel(value) {
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value) ? value.replace(' ', 'T') + 'Z' : value;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('ja-JP');
}
function phaseLabel(call) {
  if (call.blocked) return 'ブロック判定あり';
  if (call.phases.includes('post_tool_use')) return '実行後の記録あり';
  if (call.phases.includes('pre_tool_use')) return '実行前の記録';
  return '記録あり';
}
function renderValue(section, value) {
  const labels = {cmd: '実行コマンド', command: '実行コマンド', stdout: '標準出力', stderr: 'エラー出力',
    exit_code: '終了コード', workdir: '作業フォルダー', path: '対象パス', url: 'URL',
    output: '出力内容', text: 'テキスト', content: '内容'};
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.entries(value);
    if (!entries.length) section.append(node('pre', '{}'));
    for (const [key, content] of entries) {
      section.append(node('h4', labels[key] || key));
      section.append(node('pre', content === '' ? '（空の文字列）' : readable(content)));
    }
  } else section.append(node('pre', value === '' ? '（空の文字列）' : readable(value)));
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
    button.append(node('strong', call.tool_name), node('time', timeLabel(call.recorded_at)),
      node('span', phaseLabel(call), call.blocked ? 'badge badge-blocked' : 'badge'));
    button.onclick = () => { $('follow').checked = false; choose(call); renderCalls(calls); loadDetail(); };
    $('calls').append(button);
  }
}
function renderDetail(data) {
  const signature = JSON.stringify([selected?.event_id, data]);
  if (signature === detailJSON) return;
  detailJSON = signature;
  $('title').textContent = selected.tool_name;
  $('identity').textContent = `${timeLabel(selected.recorded_at)} · ${phaseLabel(selected)}`;
  $('decisions').replaceChildren();
  if (!data.decisions.length) $('decisions').append(node('p', '判定は未記録です。許可・成功を意味するものではありません。', 'hint'));
  for (const d of data.decisions) {
    const box = node('div', undefined, d.action === 'block' ? 'decision blocked' : 'decision');
    box.append(node('strong', d.action === 'block' ? 'ToolUseProxy: ブロック判定' : `ToolUseProxy: ${d.action}`),
      node('p', d.user_message || d.reason), node('small', `${d.hook_event || 'Hook未記録'} · ${timeLabel(d.created_at)}`));
    $('decisions').append(box);
  }
  $('io').replaceChildren();
  for (const [label, key] of [['入力', 'tool_input'], ['出力', 'tool_response']]) {
    const event = [...data.events].reverse().find(item => Object.hasOwn(item.payload, key));
    const section = node('article');
    section.append(node('h3', label));
    if (!event) section.append(node('p', 'まだ記録がありません', 'hint'));
    if (event) renderValue(section, event.payload[key]);
    $('io').append(section);
  }
  const raw = node('details');
  raw.append(node('summary', `技術的な詳細・元の記録（${data.events.length}件）`));
  raw.append(node('p', `Call: ${selected.tool_use_id || '未記録'} · Session: ${selected.session_id || '未記録'}`, 'hint'));
  for (const event of data.events) {
    raw.append(node('h3', `${event.phase} · ${event.recorded_at}`));
    if (event.truncated) raw.append(node('p', '大きな記録のため先頭128K文字のみ表示しています。', 'hint'));
    raw.append(node('pre', JSON.stringify(event.payload, null, 2)));
  }
  if (data.events.some(event => event.truncated)) $('io').append(node('p', 'サイズ制限によりI/Oを抽出できない記録があります。下の保存イベントを確認してください。', 'hint'));
  $('io').append(raw);
  if (!data.events.length) $('io').append(node('p', 'この記録はDBにありません。', 'empty'));
}
async function loadDetail() {
  const current = selected;
  if (!current) return;
  try {
    const data = await get(`api/detail?id=${encodeURIComponent(current.event_id)}`);
    if (selected === current) renderDetail(data);
  } catch (error) {
    if (selected === current) {
      $('connection').textContent = `再接続待ち · ${error.message}`;
      $('connection').className = 'offline';
    }
  }
}
async function refresh() {
  try {
    const data = await get('api/events');
    $('database').textContent = data.database;
    if (data.calls.length && (!selected || ($('follow').checked && selected.event_id !== data.calls[0].event_id))) choose(data.calls[0]);
    if (selected) selected = data.calls.find(call => callKey(call) === callKey(selected)) || selected;
    renderCalls(data.calls);
    const current = selected;
    if (current) {
      const detail = await get(`api/detail?id=${encodeURIComponent(current.event_id)}`);
      if (selected === current) renderDetail(detail);
    }
    $('connection').textContent = '● 接続中 · 自動更新';
    $('connection').className = 'online';
    $('updated').textContent = `最終確認 ${new Date().toLocaleTimeString('ja-JP')}`;
  } catch (error) {
    $('connection').textContent = `再接続待ち · ${error.message}`;
    $('connection').className = 'offline';
  } finally { setTimeout(refresh, 1000); }
}
refresh();
