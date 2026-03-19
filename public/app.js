const passwordLoginForm = document.getElementById('passwordLoginForm');
const totpLoginForm = document.getElementById('totpLoginForm');
const confirmEnrollmentForm = document.getElementById('confirmEnrollmentForm');
const recoveryRotateForm = document.getElementById('recoveryRotateForm');
const passwordChangeForm = document.getElementById('passwordChangeForm');
const totpEntryForm = document.getElementById('totpEntryForm');
const startEnrollmentButton = document.getElementById('startEnrollmentButton');
const refreshSessionButton = document.getElementById('refreshSessionButton');
const logoutButton = document.getElementById('logoutButton');

const activityResult = document.getElementById('activityResult');
const recoveryResult = document.getElementById('recoveryResult');
const accountActionResult = document.getElementById('accountActionResult');
const qrMount = document.getElementById('qrMount');
const enrollmentMeta = document.getElementById('enrollmentMeta');
const sessionStatus = document.getElementById('sessionStatus');
const totpEntryResult = document.getElementById('totpEntryResult');
const totpEntriesMeta = document.getElementById('totpEntriesMeta');
const totpEntriesList = document.getElementById('totpEntriesList');

let entryRefreshTimer = null;
let entryState = new Map();
let lastEntries = [];

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || '请求失败。');
  }
  return payload;
}

function setMessage(element, text) {
  element.textContent = text;
}

function renderEnrollment(enrollment) {
  if (!enrollment) {
    qrMount.textContent = '暂无正在进行的绑定任务。';
    enrollmentMeta.textContent = '暂无正在进行的绑定任务。';
    return;
  }

  qrMount.innerHTML = enrollment.qrSvg;
  enrollmentMeta.textContent = [
    `开始时间: ${enrollment.startedAt}`,
    `过期时间: ${enrollment.expiresAt}`,
    `密钥预览: ${enrollment.secretPreview}`,
    `otpauth URL: ${enrollment.otpauthUrl}`
  ].join('\n');
}

function stopEntryRefreshLoop() {
  if (entryRefreshTimer) {
    clearInterval(entryRefreshTimer);
    entryRefreshTimer = null;
  }
}

function startEntryRefreshLoop() {
  if (entryRefreshTimer) {
    return;
  }

  entryRefreshTimer = setInterval(() => {
    refreshTotpEntries({ silent: true });
  }, 1000);
}

function pruneEntryState(entries) {
  const next = new Map();
  for (const entry of entries) {
    next.set(entry.id, entryState.get(entry.id) || { expanded: false });
  }
  entryState = next;
}

function renderTotpEntries(entries) {
  lastEntries = entries;
  pruneEntryState(entries);

  if (!entries.length) {
    totpEntriesList.innerHTML = '<div class="message-box">还没有录入任何 TOTP 条目。</div>';
    return;
  }

  totpEntriesList.innerHTML = entries.map((entry) => {
    const state = entryState.get(entry.id) || { expanded: false };
    const codeContent = state.expanded
      ? `
        <div class="totp-entry-code-row">
          <div class="totp-entry-code">${escapeHtml(entry.currentCode)}</div>
          <button type="button" class="btn btn-outline btn-sm copy-code-button" data-entry-id="${entry.id}">复制验证码</button>
        </div>
        <div class="totp-entry-meta">
          <span>剩余: ${entry.secondsRemaining}s</span>
          <span>Secret: ${escapeHtml(entry.secretPreview)}</span>
        </div>
      `
      : '<div class="totp-entry-hidden">已折叠，展开后查看当前验证码。</div>';

    return `
      <article class="totp-entry-card">
        <div class="totp-entry-head">
          <div>
            <div class="totp-entry-title">${escapeHtml(entry.issuer)}</div>
            <div class="totp-entry-subtitle">${escapeHtml(entry.account)}</div>
          </div>
          <div class="totp-entry-actions">
            <div class="status-badge">${entry.secondsRemaining}s</div>
            <button type="button" class="btn btn-ghost btn-sm toggle-entry-button" data-entry-id="${entry.id}">
              ${state.expanded ? '隐藏验证码' : '显示验证码'}
            </button>
          </div>
        </div>
        ${codeContent}
      </article>
    `;
  }).join('');
}

async function refreshTotpEntries({ silent = false } = {}) {
  try {
    const payload = await api('/api/totp-entries', { method: 'GET' });
    const entries = payload.entries || [];
    renderTotpEntries(entries);
    setMessage(totpEntriesMeta, `共 ${entries.length} 条，可按需展开并一键复制验证码。`);
  } catch (error) {
    stopEntryRefreshLoop();
    setMessage(totpEntriesMeta, error.message);
    if (!silent) {
      totpEntriesList.innerHTML = '<div class="message-box">登录后将在这里显示你的 TOTP 条目。</div>';
    }
  }
}

async function refreshStatus() {
  try {
    const status = await api('/api/status', { method: 'GET' });
    if (!status.initialized) {
      setMessage(sessionStatus, '管理员账户未初始化');
      renderEnrollment(null);
      stopEntryRefreshLoop();
      setMessage(activityResult, '请先在服务器上运行 npm run init-admin -- --password="您的长密码"。');
      setMessage(totpEntriesMeta, '管理员账户未初始化。');
      totpEntriesList.innerHTML = '<div class="message-box">初始化管理员账户后即可录入 TOTP 条目。</div>';
      return;
    }
    await refreshSession();
  } catch (error) {
    setMessage(sessionStatus, error.message);
  }
}

async function refreshSession() {
  try {
    const payload = await api('/api/me', { method: 'GET' });
    renderEnrollment(payload.admin.pendingEnrollment);

    const markers = [];
    if (payload.admin.session?.bootstrap) {
      markers.push('引导会话');
    }
    if (payload.admin.session?.usedRecoveryCode) {
      markers.push('已通过恢复码登录');
    }

    setMessage(
      sessionStatus,
      markers.length ? `已认证的管理员 (${markers.join(' / ')})` : '已认证的管理员'
    );

    await refreshTotpEntries();
    startEntryRefreshLoop();
  } catch (error) {
    setMessage(sessionStatus, '当前未登录');
    renderEnrollment(null);
    stopEntryRefreshLoop();
    setMessage(totpEntriesMeta, '当前未登录。');
    totpEntriesList.innerHTML = '<div class="message-box">登录后将在这里显示你的 TOTP 条目。</div>';
  }
}

passwordLoginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setMessage(activityResult, '正在验证密码...');
  const formData = new FormData(passwordLoginForm);

  try {
    const payload = await api('/api/login/password', {
      method: 'POST',
      body: JSON.stringify({
        password: formData.get('password')
      })
    });

    if (payload.challengeId) {
      totpLoginForm.elements.challengeId.value = payload.challengeId;
      setMessage(activityResult, '密码验证通过，请输入 TOTP 验证码或恢复码完成登录。');
    } else {
      setMessage(activityResult, '密码验证通过，请继续完成当前管理员账户的 TOTP 绑定。');
    }

    await refreshStatus();
  } catch (error) {
    setMessage(activityResult, error.message);
  }
});

totpLoginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setMessage(activityResult, '正在核对二步验证码...');
  const formData = new FormData(totpLoginForm);

  try {
    await api('/api/login/totp', {
      method: 'POST',
      body: JSON.stringify({
        challengeId: formData.get('challengeId'),
        code: formData.get('code')
      })
    });
    setMessage(activityResult, '登录成功。');
    await refreshStatus();
  } catch (error) {
    setMessage(activityResult, error.message);
  }
});

startEnrollmentButton.addEventListener('click', async () => {
  setMessage(accountActionResult, '正在生成新的绑定二维码...');
  try {
    const payload = await api('/api/account/totp/enroll', {
      method: 'POST',
      body: '{}'
    });
    renderEnrollment(payload.enrollment);
    setMessage(accountActionResult, '新的绑定二维码已生成，请在验证器中扫描后输入当前验证码确认。');
    await refreshStatus();
  } catch (error) {
    setMessage(accountActionResult, error.message);
  }
});

confirmEnrollmentForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setMessage(accountActionResult, '正在确认绑定...');
  const formData = new FormData(confirmEnrollmentForm);

  try {
    const payload = await api('/api/account/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({
        code: formData.get('code')
      })
    });
    setMessage(accountActionResult, 'TOTP 已启用。');
    setMessage(recoveryResult, `请立即保存恢复码：${payload.recoveryCodes.join(' ')}`);
    confirmEnrollmentForm.reset();
    await refreshStatus();
  } catch (error) {
    setMessage(accountActionResult, error.message);
  }
});

recoveryRotateForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setMessage(recoveryResult, '正在重新生成恢复码...');
  const formData = new FormData(recoveryRotateForm);

  try {
    const payload = await api('/api/account/recovery-codes/regenerate', {
      method: 'POST',
      body: JSON.stringify({
        password: formData.get('password')
      })
    });
    setMessage(recoveryResult, `新的恢复码：${payload.recoveryCodes.join(' ')}`);
    recoveryRotateForm.reset();
    await refreshStatus();
  } catch (error) {
    setMessage(recoveryResult, error.message);
  }
});

passwordChangeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setMessage(accountActionResult, '正在更新密码...');
  const formData = new FormData(passwordChangeForm);

  try {
    await api('/api/account/password/change', {
      method: 'POST',
      body: JSON.stringify({
        currentPassword: formData.get('currentPassword'),
        nextPassword: formData.get('nextPassword')
      })
    });
    setMessage(accountActionResult, '密码已更新。');
    passwordChangeForm.reset();
    await refreshStatus();
  } catch (error) {
    setMessage(accountActionResult, error.message);
  }
});

totpEntryForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setMessage(totpEntryResult, '正在保存新的 TOTP 条目...');
  const formData = new FormData(totpEntryForm);

  try {
    await api('/api/totp-entries', {
      method: 'POST',
      body: JSON.stringify({
        issuer: formData.get('issuer'),
        account: formData.get('account'),
        secret: formData.get('secret')
      })
    });
    setMessage(totpEntryResult, '条目已保存。');
    totpEntryForm.reset();
    await refreshTotpEntries();
    startEntryRefreshLoop();
  } catch (error) {
    setMessage(totpEntryResult, error.message);
  }
});

totpEntriesList.addEventListener('click', async (event) => {
  const toggleButton = event.target.closest('.toggle-entry-button');
  if (toggleButton) {
    const entryId = Number(toggleButton.dataset.entryId);
    const state = entryState.get(entryId) || { expanded: false };
    entryState.set(entryId, { expanded: !state.expanded });
    renderTotpEntries(lastEntries);
    return;
  }

  const copyButton = event.target.closest('.copy-code-button');
  if (copyButton) {
    const entryId = Number(copyButton.dataset.entryId);
    const entry = lastEntries.find((item) => item.id === entryId);
    if (!entry) {
      return;
    }

    try {
      await navigator.clipboard.writeText(entry.currentCode);
      setMessage(totpEntriesMeta, `${entry.issuer} / ${entry.account} 的验证码已复制。`);
    } catch {
      setMessage(totpEntriesMeta, '复制失败，请检查浏览器剪贴板权限。');
    }
  }
});

refreshSessionButton.addEventListener('click', refreshStatus);

logoutButton.addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
  } catch (_) {
    // Ignore logout errors to keep the UI moving.
  }
  await refreshStatus();
});

refreshStatus();
