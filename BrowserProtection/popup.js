// Xdows Security 网络防护 - 弹窗逻辑

// HTML 中用 data-i18n 属性标记, 由 JS 显式替换(chrome.i18n 在 popup 中可靠)
function localizePage() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    const msg = chrome.i18n.getMessage(key);
    if (msg !== undefined && msg !== '') {
      el.textContent = msg;
    }
  });
}

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  const diff = now - d;
  if (diff < 60 * 1000) return chrome.i18n.getMessage('timeJustNow');
  if (diff < 60 * 60 * 1000) return chrome.i18n.getMessage('timeMinutesAgo', [String(Math.floor(diff / 60000))]);
  const h = d.getHours().toString().padStart(2, '0');
  const m = d.getMinutes().toString().padStart(2, '0');
  return h + ':' + m;
}

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function renderRecent(recent) {
  const list = document.getElementById('recentList');
  if (!recent || recent.length === 0) {
    list.innerHTML = '<div class="empty">' + chrome.i18n.getMessage('noRecent') + '</div>';
    return;
  }
  list.innerHTML = '';
  for (const item of recent) {
    const row = document.createElement('div');
    row.className = 'recent-item';
    const dot = document.createElement('span');
    dot.className = 'dot';
    const url = document.createElement('span');
    url.className = 'url';
    url.textContent = extractDomain(item.url);
    const time = document.createElement('span');
    time.className = 'time';
    time.textContent = formatTime(item.time);
    row.appendChild(dot);
    row.appendChild(url);
    row.appendChild(time);
    list.appendChild(row);
  }
}

async function init() {
  try {
    // 规则数由 background 在安装时从 rules.json 计算并缓存
    const { xdows_rule_count: ruleCount = 40 } = await chrome.storage.local.get('xdows_rule_count');
    document.getElementById('ruleCount').textContent = String(ruleCount);

    const response = await chrome.runtime.sendMessage({ type: 'getStats' });
    if (response && response.stats) {
      document.getElementById('totalCount').textContent = String(response.stats.total || 0);
      renderRecent(response.recent);
    }
  } catch (e) {
    console.error('[Xdows Security] popup init failed:', e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  localizePage();
  init();
});