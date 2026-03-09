document.addEventListener('DOMContentLoaded', () => {
  const lockScreen       = document.getElementById('lock-screen');
  const vaultScreen      = document.getElementById('vault-screen');
  const masterPassword   = document.getElementById('master-password');
  const unlockBtn        = document.getElementById('unlock-btn');
  const lockErr          = document.getElementById('lock-error');

  const lockBtn          = document.getElementById('lock-btn');
  const searchInput      = document.getElementById('search-input');
  const resultsContainer = document.getElementById('results-container');
  const vaultMsg         = document.getElementById('vault-msg');

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  function showLock() {
    lockScreen.classList.add('active');
    vaultScreen.classList.remove('active');
    resultsContainer.innerHTML = '';
    searchInput.value = '';
    masterPassword.focus();
  }

  function showVault() {
    lockScreen.classList.remove('active');
    vaultScreen.classList.add('active');
    vaultMsg.textContent = '';
    searchInput.focus();
    performSearch('');
  }

  function setLockError(msg) {
    lockErr.textContent = msg;
  }

  function clearLockError() {
    lockErr.textContent = '';
  }

  function setUnlockBusy(busy) {
    unlockBtn.disabled = busy;
    unlockBtn.textContent = busy ? 'Working...' : 'Unlock';
  }

  // Safely clear the password field. Called only after all uses of
  // masterPassword.value are complete so the value is not wiped mid-flow.
  function clearPasswordField() {
    masterPassword.value = '';
  }

  // --------------------------------------------------------------------------
  // Native host communication
  // --------------------------------------------------------------------------

  function sendCommand(command, extra = {}) {
    return browser.runtime.sendMessage({ command, ...extra });
  }

  // --------------------------------------------------------------------------
  // Unlock flow
  // --------------------------------------------------------------------------
  //
  // The flow is:
  //
  //   1. Send "unlock" with the typed password.
  //   2a. If status === "ok":  vault existed and is now loaded. Show vault UI.
  //   2b. If the error message indicates no vault exists yet ("init_vault"):
  //         Ask the user to confirm they want to create a new vault.
  //         If confirmed, send "init_vault" with the same password.
  //         On success, send "unlock" again with the same password.
  //         On any failure, show the error and leave the password field intact
  //         so the user does not have to retype.
  //   2c. Any other error (wrong password, decryption failure, I/O error):
  //         Show the error message. Leave the password field intact.
  //
  // The password field is cleared only after all use of its value is done,
  // whether that is after a successful unlock or after an init+unlock chain.

  async function attemptUnlock(password) {
    const response = await sendCommand('unlock', { password });

    if (response && response.status === 'ok') {
      clearPasswordField();
      clearLockError();
      showVault();
      return;
    }

    const message = response?.message ?? 'Unlock failed';

    // The native host includes "init_vault" in the error message when the
    // vault file does not exist, as a machine-readable hint to the caller.
    const vaultMissing = message.includes('init_vault');

    if (vaultMissing) {
      await attemptInitAndUnlock(password, message);
      return;
    }

    // Wrong password, decryption failure, I/O error, or any other condition.
    // Leave the password field intact so the user can correct and retry.
    setLockError(message);
  }

  async function attemptInitAndUnlock(password, originalError) {
    // Show the resolved vault path from the error message so the user
    // understands where the vault will be created before confirming.
    const pathMatch = originalError.match(/at:\s*(.+?)\./);
    const pathHint  = pathMatch
      ? `\n\nVault will be created at:\n${pathMatch[1]}`
      : '';

    const confirmed = window.confirm(
      'No vault was found for this installation.' +
      pathHint +
      '\n\nCreate a new vault with this password?'
    );

    if (!confirmed) {
      setLockError('Vault creation cancelled.');
      return;
    }

    setLockError('Creating vault…');

    const initResponse = await sendCommand('init_vault', { password });

    if (!initResponse || initResponse.status !== 'ok') {
      setLockError(
        'Failed to create vault: ' +
        (initResponse?.message ?? 'Unknown error')
      );
      // Leave the password field intact; the user may want to retry.
      return;
    }

    // Vault file is now on disk. Unlock it with the same password.
    setLockError('Vault created. Unlocking…');

    const unlockResponse = await sendCommand('unlock', { password });

    if (unlockResponse && unlockResponse.status === 'ok') {
      clearPasswordField();
      clearLockError();
      showVault();
    } else {
      // The vault was created but the immediate unlock failed. This should
      // not happen under normal conditions (the password was just used to
      // create the vault), but surfacing it gives the user a chance to retry.
      setLockError(
        'Vault created but unlock failed: ' +
        (unlockResponse?.message ?? 'Unknown error')
      );
    }
  }

  // --------------------------------------------------------------------------
  // Event listeners
  // --------------------------------------------------------------------------

  // Check initial lock state on popup open.
  sendCommand('ping').then((response) => {
    if (response && response.status === 'ok') {
      if (response.is_unlocked) {
        showVault();
      } else {
        showLock();
      }
    } else {
      setLockError('Native host not responding');
    }
  }).catch(() => {
    setLockError('Failed to communicate with host');
  });

  // Unlock button.
  unlockBtn.addEventListener('click', async () => {
    const password = masterPassword.value;
    if (!password) {
      setLockError('Please enter your master password');
      return;
    }

    clearLockError();
    setUnlockBusy(true);

    try {
      await attemptUnlock(password);
    } catch (e) {
      setLockError('Communication error');
    } finally {
      setUnlockBusy(false);
    }
  });

  // Enter key in the password field triggers unlock.
  masterPassword.addEventListener('keyup', (e) => {
    if (e.key === 'Enter') {
      unlockBtn.click();
    }
  });

  // Lock button.
  lockBtn.addEventListener('click', () => {
    sendCommand('lock').then(() => {
      showLock();
    });
  });

  // --------------------------------------------------------------------------
  // Search
  // --------------------------------------------------------------------------

  let searchTimeout = null;
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      performSearch(searchInput.value);
    }, 200);
  });

  function performSearch(query) {
    sendCommand('search', { query }).then(response => {
      if (response && response.status === 'ok') {
        renderResults(response.results);
      } else if (response && response.message === 'Locked') {
        showLock();
      }
    });
  }

  // --------------------------------------------------------------------------
  // Results rendering
  // --------------------------------------------------------------------------

  function renderResults(results) {
    resultsContainer.innerHTML = '';

    if (results.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'entry-item';
      empty.textContent = 'No matching entries found.';
      empty.style.color = '#666';
      resultsContainer.appendChild(empty);
      return;
    }

    results.forEach(entry => {
      const item = document.createElement('div');
      item.className = 'entry-item';

      const info = document.createElement('div');
      info.className = 'entry-info';

      const pk = document.createElement('div');
      pk.className = 'entry-pk';
      pk.textContent = entry.primary_key;

      const user = document.createElement('div');
      user.className = 'entry-user';
      user.textContent = entry.username || 'No username';

      info.appendChild(pk);
      info.appendChild(user);

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => {
        vaultMsg.textContent = 'Copying…';
        vaultMsg.style.color = '#333';
        sendCommand('copy', { uuid: entry.uuid }).then(res => {
          if (res && res.status === 'ok') {
            vaultMsg.textContent = 'Copied to clipboard!';
            vaultMsg.style.color = '#008000';
            setTimeout(() => { vaultMsg.textContent = ''; }, 3000);
          } else {
            vaultMsg.textContent = res?.message || 'Error copying';
            vaultMsg.style.color = '#d10000';
          }
        });
      });

      item.appendChild(info);
      item.appendChild(copyBtn);
      resultsContainer.appendChild(item);
    });
  }
});
