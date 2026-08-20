// Xdows Security 网络防护 - 后台服务
// 1) declarativeNetRequest block 动作阻断请求(地址栏 URL 保持不变)
// 2) webNavigation.onErrorOccurred 检测 ERR_BLOCKED_BY_CLIENT
// 3) 通过 CDP Page.setDocumentContent 将浏览器错误页替换为自定义 WinUI3 风格拦截页
// 4) 统计拦截事件并持久化, 供 popup 弹窗读取

const STATS_KEY = 'xdows_block_stats';
const RECENT_KEY = 'xdows_recent_blocks';
const MAX_RECENT = 20;

let blockedHtmlTemplate = null;
let iconDataUri = null;

// ---- 模板与图标资源(缓存, 注入时替换占位符) ----
async function ensureAssets() {
  if (!blockedHtmlTemplate) {
    const resp = await fetch(chrome.runtime.getURL('blocked.html'));
    blockedHtmlTemplate = await resp.text();
  }
  if (!iconDataUri) {
    const iconResp = await fetch(chrome.runtime.getURL('icons/icon128.png'));
    const blob = await iconResp.blob();
    iconDataUri = await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result);
      reader.readAsDataURL(blob);
    });
  }
}

// 把模板中的 {{MSG_xxx}} 占位符替换为当前语言的本地化文本
function localizeTemplate(tpl) {
  return tpl.replace(/\{\{MSG_(\w+)\}\}/g, (_m, key) => {
    const msg = chrome.i18n.getMessage(key);
    return msg !== undefined && msg !== '' ? msg : _m;
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---- 拦截统计 ----
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
  try {
    const now = Date.now();
    const url = info.request.url || '';
    const ruleId = info.rule.ruleId;

    const { [STATS_KEY]: stats = {} } = await chrome.storage.local.get(STATS_KEY);
    stats.total = (stats.total || 0) + 1;
    stats.lastTime = now;
    stats[ruleId] = (stats[ruleId] || 0) + 1;

    const { [RECENT_KEY]: recent = [] } = await chrome.storage.local.get(RECENT_KEY);
    recent.unshift({ url, ruleId, time: now });
    if (recent.length > MAX_RECENT) recent.length = MAX_RECENT;

    await chrome.storage.local.set({ [STATS_KEY]: stats, [RECENT_KEY]: recent });
  } catch (e) {
    console.error('[Xdows Security] failed to record block:', e);
  }
});

// ---- 拦截页注入: block 后 URL 不变, 用 CDP 把错误页替换为自定义拦截页 ----
chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
  // 仅主框架 + 仅 DNR block 产生的错误
  if (details.frameId !== 0) return;
  if (!details.error || !details.error.includes('ERR_BLOCKED_BY_CLIENT')) return;

  const tabId = details.tabId;
  const blockedUrl = details.url;
  try {
    await ensureAssets();
    const html = localizeTemplate(blockedHtmlTemplate)
      .replaceAll('{{BLOCKED_URL}}', escapeHtml(blockedUrl))
      .replaceAll('{{ICON_URL}}', iconDataUri);

    await chrome.debugger.attach({ tabId }, '1.3');
    try {
      const { frameTree } = await chrome.debugger.sendCommand({ tabId }, 'Page.getFrameTree');
      const mainFrameId = frameTree?.frame?.id;
      if (mainFrameId) {
        // 错误页帧可能尚未完全就绪, 带重试注入
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            await chrome.debugger.sendCommand(
              { tabId },
              'Page.setDocumentContent',
              { frameId: mainFrameId, html }
            );
            break;
          } catch (e) {
            if (attempt === 2) throw e;
            await sleep(150);
          }
        }
      }
    } finally {
      await chrome.debugger.detach({ tabId });
    }
  } catch (e) {
    // 注入失败时保持浏览器默认错误页, 不影响拦截本身
    console.error('[Xdows Security] failed to inject block page:', e);
  }
});

// 供 popup 弹窗查询统计
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'getStats') {
    (async () => {
      const { [STATS_KEY]: stats = {} } = await chrome.storage.local.get(STATS_KEY);
      const { [RECENT_KEY]: recent = [] } = await chrome.storage.local.get(RECENT_KEY);
      sendResponse({ stats, recent });
    })();
    return true; // 异步响应
  }
});

chrome.runtime.onInstalled.addListener(async () => {
  // 安装/更新时统计静态规则数, 供 popup 显示
  try {
    const resp = await fetch(chrome.runtime.getURL('rules.json'));
    const rules = await resp.json();
    await chrome.storage.local.set({ xdows_rule_count: Array.isArray(rules) ? rules.length : 0 });
  } catch (e) {
    console.error('[Xdows Security] failed to count rules:', e);
  }
  console.log('[Xdows Security] 浏览器防护已安装');
});