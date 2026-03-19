const passwordLoginForm = document.getElementById('passwordLoginForm');
const totpLoginForm = document.getElementById('totpLoginForm');
const confirmEnrollmentForm = document.getElementById('confirmEnrollmentForm');
const recoveryRotateForm = document.getElementById('recoveryRotateForm');
const passwordChangeForm = document.getElementById('passwordChangeForm');
const startEnrollmentButton = document.getElementById('startEnrollmentButton');
const refreshSessionButton = document.getElementById('refreshSessionButton');
const logoutButton = document.getElementById('logoutButton');

const activityResult = document.getElementById('activityResult');
const recoveryResult = document.getElementById('recoveryResult');
const accountActionResult = document.getElementById('accountActionResult');
const meResult = document.getElementById('meResult');
const qrMount = document.getElementById('qrMount');
const enrollmentMeta = document.getElementById('enrollmentMeta');
const sessionStatus = document.getElementById('sessionStatus');

function pretty(data) {
  return JSON.stringify(data, null, 2);
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

function renderEnrollment(enrollment) {
  if (!enrollment) {
    qrMount.textContent = '暂无正在进行的绑定任务。';
    enrollmentMeta.textContent = '暂无正在进行的绑定任务。';
    return;
  }

  qrMount.innerHTML = enrollment.qrSvg;
  enrollmentMeta.textContent = pretty({
    startedAt: enrollment.startedAt,
    expiresAt: enrollment.expiresAt,
    secretPreview: enrollment.secretPreview,
    otpauthUrl: enrollment.otpauthUrl
  });
}

async function refreshStatus() {
  try {
    const status = await api('/api/status', { method: 'GET' });
    if (!status.initialized) {
      sessionStatus.textContent = '管理员账户未初始化';
      meResult.textContent = '请先在服务器上运行 npm run init-admin -- --password="您的长密码"。';
      renderEnrollment(null);
      return;
    }
    await refreshSession();
  } catch (error) {
    sessionStatus.textContent = error.message;
  }
}

async function refreshSession() {
  try {
    const payload = await api('/api/me', { method: 'GET' });
    meResult.textContent = pretty(payload);
    renderEnrollment(payload.admin.pendingEnrollment);

    const markers = [];
    if (payload.admin.session?.bootstrap) {
      markers.push('引导会话');
    }
    if (payload.admin.session?.usedRecoveryCode) {
      markers.push('已通过备用恢复码登录');
    }
    sessionStatus.textContent = markers.length
      ? `已认证的管理员 (${markers.join(' / ')})`
      : '已认证的管理员';
  } catch (error) {
    meResult.textContent = error.message;
    sessionStatus.textContent = '当前未登录';
    renderEnrollment(null);
  }
}

passwordLoginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  activityResult.textContent = '正在验证密码...';
  const formData = new FormData(passwordLoginForm);

  try {
    const payload = await api('/api/login/password', {
      method: 'POST',
      body: JSON.stringify({
        password: formData.get('password')
      })
    });
    activityResult.textContent = pretty(payload);
    if (payload.challengeId) {
      totpLoginForm.elements.challengeId.value = payload.challengeId;
    }
    await refreshStatus();
  } catch (error) {
    activityResult.textContent = error.message;
  }
});

totpLoginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  activityResult.textContent = '正在核对二步验证...';
  const formData = new FormData(totpLoginForm);

  try {
    const payload = await api('/api/login/totp', {
      method: 'POST',
      body: JSON.stringify({
        challengeId: formData.get('challengeId'),
        code: formData.get('code')
      })
    });
    activityResult.textContent = pretty(payload);
    await refreshStatus();
  } catch (error) {
    activityResult.textContent = error.message;
  }
});

startEnrollmentButton.addEventListener('click', async () => {
  accountActionResult.textContent = '正在生成全新的绑定二维码...';
  try {
    const payload = await api('/api/account/totp/enroll', {
      method: 'POST',
      body: '{}'
    });
    accountActionResult.textContent = pretty(payload);
    renderEnrollment(payload.enrollment);
    await refreshStatus();
  } catch (error) {
    accountActionResult.textContent = error.message;
  }
});

confirmEnrollmentForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  accountActionResult.textContent = '正在确认待绑定状态...';
  const formData = new FormData(confirmEnrollmentForm);

  try {
    const payload = await api('/api/account/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({
        code: formData.get('code')
      })
    });
    accountActionResult.textContent = pretty(payload);
    recoveryResult.textContent = pretty({
      message: '请立刻保存这些恢复码！它们未来不会再显示。',
      recoveryCodes: payload.recoveryCodes
    });
    confirmEnrollmentForm.reset();
    await refreshStatus();
  } catch (error) {
    accountActionResult.textContent = error.message;
  }
});

recoveryRotateForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  recoveryResult.textContent = '重新生成恢复码中...';
  const formData = new FormData(recoveryRotateForm);

  try {
    const payload = await api('/api/account/recovery-codes/regenerate', {
      method: 'POST',
      body: JSON.stringify({
        password: formData.get('password')
      })
    });
    recoveryResult.textContent = pretty(payload);
    recoveryRotateForm.reset();
    await refreshStatus();
  } catch (error) {
    recoveryResult.textContent = error.message;
  }
});

passwordChangeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  accountActionResult.textContent = '正在更新密码...';
  const formData = new FormData(passwordChangeForm);

  try {
    const payload = await api('/api/account/password/change', {
      method: 'POST',
      body: JSON.stringify({
        currentPassword: formData.get('currentPassword'),
        nextPassword: formData.get('nextPassword')
      })
    });
    accountActionResult.textContent = pretty(payload);
    passwordChangeForm.reset();
    await refreshStatus();
  } catch (error) {
    accountActionResult.textContent = error.message;
  }
});

refreshSessionButton.addEventListener('click', refreshStatus);
logoutButton.addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
  } catch (_) {
    // 忽略登出时的错误
  }
  await refreshStatus();
});

refreshStatus();
