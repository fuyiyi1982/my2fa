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
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
}

function renderEnrollment(enrollment) {
  if (!enrollment) {
    qrMount.textContent = 'No pending enrollment.';
    enrollmentMeta.textContent = 'No pending enrollment.';
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
      sessionStatus.textContent = 'Admin account is not initialized';
      meResult.textContent = 'Run `npm run init-admin -- --password="your-long-password"` on the server first.';
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
      markers.push('bootstrap session');
    }
    if (payload.admin.session?.usedRecoveryCode) {
      markers.push('recovered with backup code');
    }
    sessionStatus.textContent = markers.length
      ? `Authenticated admin (${markers.join(', ')})`
      : 'Authenticated admin';
  } catch (error) {
    meResult.textContent = error.message;
    sessionStatus.textContent = 'No active session';
    renderEnrollment(null);
  }
}

passwordLoginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  activityResult.textContent = 'Verifying password...';
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
  activityResult.textContent = 'Checking second factor...';
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
  accountActionResult.textContent = 'Creating a fresh enrollment QR code...';
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
  accountActionResult.textContent = 'Confirming pending enrollment...';
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
      message: 'Save these recovery codes now. They will not be shown again.',
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
  recoveryResult.textContent = 'Rotating recovery codes...';
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
  accountActionResult.textContent = 'Updating password...';
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
    // Ignore logout errors.
  }
  await refreshStatus();
});

refreshStatus();
