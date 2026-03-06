document.addEventListener('DOMContentLoaded', () => {
    const lockScreen = document.getElementById('lock-screen');
    const vaultScreen = document.getElementById('vault-screen');
    const masterPassword = document.getElementById('master-password');
    const unlockBtn = document.getElementById('unlock-btn');
    const lockErr = document.getElementById('lock-error');

    const lockBtn = document.getElementById('lock-btn');
    const searchInput = document.getElementById('search-input');
    const resultsContainer = document.getElementById('results-container');
    const vaultMsg = document.getElementById('vault-msg');

    // Check initial state
    browser.runtime.sendMessage({ command: 'ping' }).then((response) => {
        if (response && response.status === 'ok') {
            if (response.is_unlocked) {
                showVault();
            } else {
                showLock();
            }
        } else {
            lockErr.textContent = "Native host not responding";
        }
    }).catch(e => {
        lockErr.textContent = "Failed to communicate with host";
    });

    // Unlock
    unlockBtn.addEventListener('click', () => {
        const password = masterPassword.value;
        if (!password) {
            lockErr.textContent = "Please enter password";
            return;
        }

        unlockBtn.disabled = true;
        lockErr.textContent = "";

        browser.runtime.sendMessage({
            command: 'unlock',
            password: password
        }).then((response) => {
            unlockBtn.disabled = false;
            if (response && response.status === 'ok') {
                masterPassword.value = '';
                showVault();
            } else {
                lockErr.textContent = response?.message || "Unlock failed";
            }
        }).catch(e => {
            unlockBtn.disabled = false;
            lockErr.textContent = "Communication error";
        });
    });

    // Handle enter key in password field
    masterPassword.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            unlockBtn.click();
        }
    });

    // Lock
    lockBtn.addEventListener('click', () => {
        browser.runtime.sendMessage({ command: 'lock' }).then(() => {
            showLock();
        });
    });

    // Search
    let searchTimeout = null;
    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            performSearch(searchInput.value);
        }, 200);
    });

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

        // Perform initial search
        performSearch('');
    }

    function performSearch(query) {
        browser.runtime.sendMessage({
            command: 'search',
            query: query
        }).then(response => {
            if (response && response.status === 'ok') {
                renderResults(response.results);
            } else if (response && response.message === 'Locked') {
                showLock();
            }
        });
    }

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
                vaultMsg.textContent = 'Copying...';
                vaultMsg.style.color = '#333';
                browser.runtime.sendMessage({
                    command: 'copy',
                    uuid: entry.uuid
                }).then(res => {
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
