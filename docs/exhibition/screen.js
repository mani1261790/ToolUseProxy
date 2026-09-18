"use strict";
(() => {
  const data = window.EXHIBITION_REPLAY;
  const byId = id => document.getElementById(id);
  if (!data || data.schema !== 1 || data.mode !== "synthetic_replay") {
    byId("case-title").textContent = "再生データを読み込めませんでした。展示ファイル一式を確認してください。";
    document.querySelectorAll("button, select").forEach(button => { button.disabled = true; });
    return;
  }
  let scenario = data.scenarios[0], position = -1, selection = 0, timer = null;
  const buttons = [...document.querySelectorAll("[data-scenario]")];
  const stop = () => { clearTimeout(timer); timer = null; byId("play").textContent = "▶ 再生する"; };
  function announce(message) { byId("announcement").textContent = message; }
  function render() {
    byId("case-label").textContent = scenario.kind;
    byId("case-title").textContent = scenario.title;
    byId("source-name").textContent = scenario.source;
    byId("progress-label").textContent = `${Math.max(0, position + 1)} / 4 工程`;
    byId("gate-value").textContent = position >= 2 ? scenario.verdict : "待機中";
    byId("gate-label").textContent = position >= 2 ? scenario.verdict : "判定前";
    byId("verdict").textContent = position >= 2 ? scenario.verdict : "未再生";
    byId("verdict").className = position >= 2 ? scenario.tone : "";
    byId("verdict-caption").textContent = position >= 2 ? scenario.proof : "再生して送信前の判定を確認します。";
    byId("receipt").textContent = "未観測";
    byId("step").disabled = position === 3;
    byId("play").textContent = timer ? "Ⅱ 一時停止" : position === 3 ? "↻ もう一度再生" : "▶ 再生する";
    document.querySelectorAll("[data-node]").forEach(node => {
      const index = Number(node.dataset.node);
      node.classList.toggle("active", index <= position);
      node.classList.toggle("stopped", index === 2 && position >= 2 && scenario.id === "protected");
    });
    document.querySelectorAll("[data-link]").forEach(link => {
      const index = Number(link.dataset.link);
      link.classList.toggle("active", index <= position && index !== 3);
      link.classList.toggle("stopped", index === 2 && position >= 2 && scenario.id === "protected");
    });
    buttons.forEach(button => {
      const selected = button.dataset.scenario === scenario.id;
      button.classList.toggle("selected", selected);
      button.setAttribute("aria-pressed", String(selected));
    });
    [...byId("timeline").children].forEach((li, index) => {
      const button = li.firstElementChild;
      button.setAttribute("aria-current", String(index === selection));
      li.querySelector(".check").textContent = index <= position ? "✓" : "—";
    });
    byId("reason-title").textContent = scenario.steps[selection][0];
    byId("reason-body").textContent = scenario.steps[selection][2];
  }
  function prepare() {
    stop(); position = -1; selection = 0;
    byId("timeline").replaceChildren();
    scenario.steps.forEach((step, index) => {
      const li = document.createElement("li"), button = document.createElement("button");
      const number = document.createElement("span"), label = document.createElement("span");
      const title = document.createElement("strong"), subtitle = document.createElement("small");
      const check = document.createElement("span");
      number.className = "number"; number.textContent = `0${index + 1}`;
      title.textContent = step[0]; subtitle.textContent = step[1]; check.className = "check";
      label.append(title, subtitle); button.append(number, label, check); li.append(button);
      button.addEventListener("click", () => { stop(); selection = index; render(); });
      byId("timeline").append(li);
    });
    render();
  }
  function advance() {
    position = Math.min(3, position + 1); selection = position;
    render(); announce(`${scenario.steps[position][0]}。${scenario.steps[position][1]}`);
  }
  function tick() {
    advance();
    if (position < 3) timer = setTimeout(tick, Number(byId("speed").value));
    else stop();
    render();
  }
  buttons.forEach(button => button.addEventListener("click", () => {
    scenario = data.scenarios.find(item => item.id === button.dataset.scenario);
    prepare(); announce(`${scenario.kind}を選択しました。`);
  }));
  byId("play").addEventListener("click", () => {
    if (timer) { stop(); render(); return; }
    if (position === 3) { position = -1; selection = 0; }
    tick();
  });
  byId("step").addEventListener("click", () => { stop(); advance(); });
  byId("reset").addEventListener("click", () => { prepare(); announce("最初の状態へ戻しました。"); });
  byId("speed").addEventListener("change", () => {
    if (timer) { clearTimeout(timer); timer = setTimeout(tick, Number(byId("speed").value)); }
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) { stop(); render(); } });
  byId("provenance").textContent = `${data.source} / Plugin ${data.version}。固定人工試験の集計から、展示用の項目だけを抽出しています。`;
  byId("record-id").textContent = `試験に用いた配布物 SHA-256: ${data.artifact}`;
  prepare();
})();
