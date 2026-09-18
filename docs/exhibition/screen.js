'use strict';
const $ = (id) => document.getElementById(id);
let selected = null;
let listJSON = '';
let detailJSON = '';
let refreshVersion = 0;
let refreshTimer;
let knownScopes = [];
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
function scopeLabel(value) { return value === null ? '未記録' : value || '（空のID）'; }
function projectLabel(id) {
  const root = knownScopes.find(scope => scope.workspace_id === id)?.workspace_root;
  return root ? `${root.split('/').filter(Boolean).pop() || root} — ${root}` : scopeLabel(id);
}
const pickers = new Map();
function makePicker(id) {
  const select = $(id);
  const label = select.parentElement;
  // Keep a hidden select as the value store; only our combobox is interactive.
  const heading = node('span', label.firstChild.textContent);
  heading.id = `${id}-label`;
  label.firstChild.replaceWith(heading);
  const wrapper = node('div', undefined, 'picker');
  const trigger = node('button', undefined, 'picker-trigger');
  trigger.type = 'button';
  trigger.id = `${id}-trigger`;
  trigger.setAttribute('role', 'combobox');
  trigger.setAttribute('aria-haspopup', 'listbox');
  trigger.setAttribute('aria-expanded', 'false');
  trigger.setAttribute('aria-labelledby', heading.id);
  const valueLabel = node('span', '', 'picker-value');
  trigger.append(valueLabel, node('span', '', 'picker-chevron'));
  const list = node('div', undefined, 'picker-options');
  list.id = `${id}-options`;
  list.setAttribute('role', 'listbox');
  list.setAttribute('aria-labelledby', heading.id);
  list.hidden = true;
  trigger.setAttribute('aria-controls', list.id);
  select.hidden = true;
  label.append(wrapper);
  wrapper.append(trigger, list);
  let active = 0;
  let search = '';
  let searchAt = 0;
  let signature = '';
  const isOpen = () => !list.hidden;
  function highlight(scroll = false) {
    [...list.children].forEach((item, index) => item.classList.toggle('active', index === active));
    if (isOpen() && list.children[active]) {
      trigger.setAttribute('aria-activedescendant', list.children[active].id);
      if (scroll) list.children[active].scrollIntoView({block: 'nearest'});
    } else trigger.removeAttribute('aria-activedescendant');
  }
  function close() {
    list.hidden = true;
    trigger.setAttribute('aria-expanded', 'false');
    trigger.removeAttribute('aria-activedescendant');
  }
  function sync() {
    const options = [...select.options];
    const next = JSON.stringify(options.map(option => [option.value, option.textContent]));
    const activeValue = list.children[active]?.dataset.value;
    if (signature !== next) {
      signature = next;
      list.replaceChildren(...options.map((option, index) => {
        const item = node('div', option.textContent, 'picker-option');
        item.id = `${id}-option-${index}`;
        item.dataset.value = option.value;
        item.setAttribute('role', 'option');
        item.onpointerdown = event => event.preventDefault();
        item.onclick = () => commit(index);
        return item;
      }));
      active = isOpen() ? Math.max(0, options.findIndex(option => option.value === activeValue)) : Math.max(0, select.selectedIndex);
    }
    valueLabel.textContent = select.selectedOptions[0]?.textContent || '';
    trigger.title = valueLabel.textContent;
    [...list.children].forEach((item, index) => item.setAttribute('aria-selected', String(index === select.selectedIndex)));
    highlight();
  }
  function open() {
    for (const picker of pickers.values()) picker.close();
    sync();
    active = Math.max(0, select.selectedIndex);
    list.hidden = false;
    trigger.setAttribute('aria-expanded', 'true');
    highlight(true);
  }
  function commit(index) {
    select.selectedIndex = index;
    sync();
    close();
    trigger.focus();
    select.dispatchEvent(new Event('change', {bubbles: true}));
  }
  trigger.onclick = () => isOpen() ? close() : open();
  trigger.onkeydown = event => {
    if (event.key === 'Tab') { close(); return; }
    if (event.key === 'Escape' && isOpen()) {
      event.preventDefault(); event.stopPropagation(); close(); return;
    }
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      if (!isOpen()) open();
      else if (event.key === 'ArrowDown') active = Math.min(list.children.length - 1, active + 1);
      else if (event.key === 'ArrowUp') active = Math.max(0, active - 1);
      if (event.key === 'Home') active = 0;
      if (event.key === 'End') active = list.children.length - 1;
      highlight(true);
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      if (isOpen()) commit(active); else open();
    } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      if (!isOpen()) open();
      search = Date.now() - searchAt > 700 ? event.key : search + event.key;
      searchAt = Date.now();
      const index = [...select.options].findIndex(option => option.textContent.toLocaleLowerCase().startsWith(search.toLocaleLowerCase()));
      if (index >= 0) { active = index; highlight(true); }
    }
  };
  document.addEventListener('pointerdown', event => { if (!wrapper.contains(event.target)) close(); });
  // A label containing several controls has ambiguous activation; use an explicit
  // non-interactive field container and the combobox's labelledby relationship.
  const field = node('div', undefined, 'picker-field');
  label.replaceWith(field);
  field.append(...label.childNodes);
  const picker = {sync, close};
  pickers.set(id, picker);
  sync();
}
makePicker('workspace');
makePicker('session');
function updateOptions(id, choices, allLabel) {
  const select = $(id);
  const value = select.value;
  if (value && !choices.some(([key]) => key === value)) {
    choices.push([value, select.selectedOptions[0].textContent]);
  }
  const signature = JSON.stringify(choices);
  if (select.dataset.options === signature) { pickers.get(id).sync(); return; }
  select.dataset.options = signature;
  select.replaceChildren(new Option(allLabel, ''), ...choices.map(([key, label]) => new Option(label, key)));
  select.value = value;
  pickers.get(id).sync();
}
function renderScopes() {
  const projects = [...new Map(knownScopes.map(scope => [JSON.stringify(scope.workspace_id), projectLabel(scope.workspace_id)])).entries()];
  updateOptions('workspace', projects, 'すべてのプロジェクト');
  const workspace = $('workspace').value;
  const sessions = knownScopes.filter(scope => !workspace || JSON.stringify(scope.workspace_id) === workspace)
    .map(scope => [JSON.stringify([scope.workspace_id, scope.session_id]),
      `${scopeLabel(scope.session_id)}${workspace ? '' : ' · ' + projectLabel(scope.workspace_id)}`]);
  updateOptions('session', sessions, 'すべてのセッション');
}
function eventQuery() {
  const params = new URLSearchParams();
  if ($('workspace').value) params.set('workspace', $('workspace').value);
  if ($('session').value) {
    const [workspace, session] = JSON.parse($('session').value);
    params.set('workspace', JSON.stringify(workspace));
    params.set('session', JSON.stringify(session));
  }
  if ($('blocked-only').checked) params.set('blocked', '1');
  return params.toString();
}
function clearDetail() {
  choose(null);
  $('title').textContent = '呼び出しを選択';
  $('identity').textContent = '';
  $('decisions').replaceChildren();
  $('io').replaceChildren(node('p', '条件に一致する呼び出しを待っています。', 'empty'));
}
function filtersChanged(projectChanged = false) {
  if (projectChanged) $('session').value = '';
  renderScopes();
  updateViewSummary();
  clearDetail();
  renderCalls([]);
  clearTimeout(refreshTimer);
  refresh();
}
function updateViewSummary() {
  const count = Number(Boolean($('workspace').value)) + Number(Boolean($('session').value)) + Number($('blocked-only').checked);
  $('filter-count').textContent = String(count);
  $('filter-count').hidden = count === 0;
  const parts = [];
  if ($('workspace').value) parts.push(projectLabel(JSON.parse($('workspace').value)));
  if ($('session').value) {
    const [workspace, session] = JSON.parse($('session').value);
    if (!$('workspace').value) parts.push(projectLabel(workspace));
    parts.push(scopeLabel(session));
  }
  if ($('blocked-only').checked) parts.push('ブロック判定のみ');
  $('active-scope').textContent = parts.join(' / ') || 'すべての呼び出し';
  $('active-scope').title = $('active-scope').textContent;
}
const settings = $('settings-dialog');
$('display-settings').onclick = () => settings.showModal();
$('close-settings').onclick = () => settings.close();
settings.addEventListener('close', () => { for (const picker of pickers.values()) picker.close(); $('display-settings').focus(); });
settings.addEventListener('click', event => {
  if (event.target !== settings) return;
  const rect = settings.getBoundingClientRect();
  if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) settings.close();
});
$('follow').onchange = () => { updateViewSummary(); clearTimeout(refreshTimer); refresh(); };
$('workspace').onchange = () => filtersChanged(true);
$('session').onchange = () => filtersChanged();
$('blocked-only').onchange = () => filtersChanged();
document.querySelector('.filters').onsubmit = event => event.preventDefault();
function renderCalls(calls) {
  const signature = JSON.stringify([calls, selected?.event_id]);
  if (signature === listJSON) return;
  listJSON = signature;
  $('calls').replaceChildren();
  $('count').textContent = `${calls.length}件`;
  if (!calls.length) $('calls').append(node('p', 'この条件に一致する呼び出しはありません。', 'empty'));
  for (const call of calls) {
    const button = node('button', undefined, 'call');
    button.classList.toggle('selected', call.event_id === selected?.event_id);
    button.setAttribute('aria-pressed', String(call.event_id === selected?.event_id));
    const top = node('div', undefined, 'call-top');
    const name = node('strong', call.tool_name);
    name.title = call.tool_name;
    const time = node('time', timeLabel(call.recorded_at).replace(/^\d+\/\d+\/\d+\s/, ''));
    time.title = timeLabel(call.recorded_at);
    top.append(name, time);
    const meta = node('div', undefined, 'call-meta');
    const context = node('span', `${projectLabel(call.workspace_id).split(' — ')[0]} · ${scopeLabel(call.session_id)}`, 'context');
    context.title = `${projectLabel(call.workspace_id)} · ${scopeLabel(call.session_id)}`;
    meta.append(node('span', phaseLabel(call), call.blocked ? 'badge badge-blocked' : 'badge'), context);
    button.append(top, meta);
    button.onclick = () => { $('follow').checked = false; choose(call); renderCalls(calls); updateViewSummary(); loadDetail(); };
    $('calls').append(button);
  }
}
function renderDetail(data) {
  const signature = JSON.stringify([selected?.event_id, data]);
  if (signature === detailJSON) return;
  detailJSON = signature;
  $('title').textContent = selected.tool_name;
  $('identity').textContent = `${timeLabel(selected.recorded_at)} · ${phaseLabel(selected)} · プロジェクト: ${projectLabel(selected.workspace_id)} · セッション: ${scopeLabel(selected.session_id)}`;
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
    raw.append(node('h3', `${event.phase} · ${timeLabel(event.recorded_at)}`));
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
  const version = ++refreshVersion;
  try {
    const [scopes, data] = await Promise.all([get('api/scopes'), get('api/events?' + eventQuery())]);
    if (version !== refreshVersion) return;
    knownScopes = scopes.scopes;
    renderScopes();
    updateViewSummary();
    $('scope-note').hidden = !scopes.truncated;
    $('scope-note').textContent = scopes.truncated ? 'セッション候補は最新1000組までです。' : '';
    $('database').textContent = data.database;
    if (data.calls.length && (!selected || ($('follow').checked && selected.event_id !== data.calls[0].event_id))) choose(data.calls[0]);
    if (selected) selected = data.calls.find(call => callKey(call) === callKey(selected)) || selected;
    if (!data.calls.length) clearDetail();
    renderCalls(data.calls);
    const current = selected;
    if (current) {
      const detail = await get(`api/detail?id=${encodeURIComponent(current.event_id)}`);
      if (version === refreshVersion && selected === current) renderDetail(detail);
    }
    if (version !== refreshVersion) return;
    $('connection').textContent = '● 接続中';
    $('connection').className = 'online';
    $('updated').textContent = `最終確認 ${new Date().toLocaleTimeString('ja-JP')}`;
  } catch (error) {
    if (version !== refreshVersion) return;
    $('connection').textContent = `再接続待ち · ${error.message}`;
    $('connection').className = 'offline';
  } finally { if (version === refreshVersion) refreshTimer = setTimeout(refresh, 1000); }
}
refresh();
