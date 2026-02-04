/**
 * Portal Gateway - SSH Keys Management
 */

let sshKeys = [];

/**
 * Show SSH Keys modal
 */
async function showSSHKeysModal() {
    console.log('[SSH Keys] Opening modal');
    showModal('ssh-keys-modal');
    await loadSSHKeys();
}

/**
 * Load SSH keys for current user
 */
async function loadSSHKeys() {
    const loading = document.getElementById('ssh-keys-loading');
    const table = document.getElementById('ssh-keys-table');
    const empty = document.getElementById('ssh-keys-empty');

    loading.style.display = 'flex';
    table.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await Portal.fetch('/api/ssh-keys');

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to load SSH keys');
        }

        const data = await response.json();
        sshKeys = (data && data.keys) ? data.keys : [];
        renderSSHKeys();
    } catch (error) {
        console.error('[SSH Keys] Error loading keys:', error);
        Portal.toast(error.message || 'Failed to load SSH keys', 'error');
    } finally {
        loading.style.display = 'none';
    }
}

/**
 * Render SSH keys table
 */
function renderSSHKeys() {
    const table = document.getElementById('ssh-keys-table');
    const tbody = document.getElementById('ssh-keys-tbody');
    const empty = document.getElementById('ssh-keys-empty');

    if (sshKeys.length === 0) {
        table.style.display = 'none';
        empty.style.display = 'block';
        return;
    }

    table.style.display = 'table';
    empty.style.display = 'none';

    tbody.innerHTML = sshKeys.map(key => `
        <tr>
            <td>${escapeHtml(key.name)}</td>
            <td><span class="badge badge-secondary">${key.key_type}</span></td>
            <td class="monospace fingerprint">${key.fingerprint}</td>
            <td>${formatDate(key.created_at)}</td>
            <td>${key.last_used_at ? formatDate(key.last_used_at) : 'Never'}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="viewPublicKey(${key.id})" title="View public key">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDeleteKey(${key.id}, '${escapeHtml(key.name).replace(/'/g, "\\'")}')">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                </button>
            </td>
        </tr>
    `).join('');
}

/**
 * Show create key form
 */
function showCreateKeyForm() {
    document.getElementById('create-key-form').style.display = 'block';
    document.getElementById('key-name').focus();
}

/**
 * Hide create key form
 */
function hideCreateKeyForm() {
    document.getElementById('create-key-form').style.display = 'none';
    document.getElementById('key-name').value = '';
}

/**
 * Submit create key form
 */
async function submitCreateKey(event) {
    event.preventDefault();

    const name = document.getElementById('key-name').value.trim();
    const keyType = document.getElementById('key-type').value;

    if (!name) {
        Portal.toast('Key name is required', 'error');
        return;
    }

    // Validate key name (alphanumeric, dashes, underscores only)
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        Portal.toast('Key name can only contain letters, numbers, dashes, and underscores', 'error');
        return;
    }

    try {
        const response = await Portal.fetch('/api/ssh-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, key_type: keyType })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to create SSH key');
        }

        const keyData = await response.json();
        console.log('[SSH Keys] Key created:', keyData.fingerprint);

        // Show the private key (only time it's available)
        showNewKeyDisplay(keyData);

        // Refresh the keys list
        await loadSSHKeys();

        // Hide the form
        hideCreateKeyForm();

        Portal.toast('SSH key generated successfully');
    } catch (error) {
        console.error('[SSH Keys] Error creating key:', error);
        Portal.toast(error.message || 'Failed to create SSH key', 'error');
    }
}

/**
 * Show new key display with private key
 */
function showNewKeyDisplay(keyData) {
    document.getElementById('new-key-name').textContent = keyData.name;
    document.getElementById('new-key-fingerprint').textContent = keyData.fingerprint;
    document.getElementById('new-private-key').value = keyData.private_key;
    document.getElementById('new-public-key').value = keyData.public_key;
    document.getElementById('new-key-display').style.display = 'block';
}

/**
 * Hide new key display
 */
function hideNewKeyDisplay() {
    document.getElementById('new-key-display').style.display = 'none';
    document.getElementById('new-private-key').value = '';
    document.getElementById('new-public-key').value = '';
}

/**
 * Copy private key to clipboard
 */
async function copyPrivateKey() {
    const textarea = document.getElementById('new-private-key');
    try {
        await navigator.clipboard.writeText(textarea.value);
        Portal.toast('Private key copied to clipboard');
    } catch (error) {
        // Fallback for older browsers
        textarea.select();
        document.execCommand('copy');
        Portal.toast('Private key copied to clipboard');
    }
}

/**
 * Copy public key to clipboard
 */
async function copyPublicKey() {
    const textarea = document.getElementById('new-public-key');
    try {
        await navigator.clipboard.writeText(textarea.value);
        Portal.toast('Public key copied to clipboard');
    } catch (error) {
        textarea.select();
        document.execCommand('copy');
        Portal.toast('Public key copied to clipboard');
    }
}

/**
 * View public key for existing key
 */
async function viewPublicKey(keyId) {
    try {
        const response = await Portal.fetch(`/api/ssh-keys/${keyId}`);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to load key');
        }

        const key = await response.json();

        if (!key || !key.public_key) {
            throw new Error('Invalid key data received');
        }

        // Show in a simple alert with copy functionality
        const publicKey = key.public_key;

        // Create a temporary modal or use prompt
        const copied = await copyToClipboard(publicKey);
        if (copied) {
            Portal.toast('Public key copied to clipboard');
        } else {
            // Show in prompt as fallback
            prompt('Public Key (Ctrl+C to copy):', publicKey);
        }
    } catch (error) {
        console.error('[SSH Keys] Error viewing key:', error);
        Portal.toast(error.message || 'Failed to load public key', 'error');
    }
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Confirm delete key
 */
function confirmDeleteKey(keyId, keyName) {
    pendingConfirmAction = async () => {
        await deleteSSHKey(keyId);
    };

    document.getElementById('confirm-title').textContent = 'Delete SSH Key';
    document.getElementById('confirm-message').textContent =
        `Are you sure you want to delete the SSH key "${keyName}"? This action cannot be undone.`;
    document.getElementById('confirm-btn').textContent = 'Delete';

    showModal('confirm-modal');
}

/**
 * Delete SSH key
 */
async function deleteSSHKey(keyId) {
    try {
        const response = await Portal.fetch(`/api/ssh-keys/${keyId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to delete SSH key');
        }

        console.log('[SSH Keys] Key deleted:', keyId);
        Portal.toast('SSH key deleted');
        closeModal('confirm-modal');
        await loadSSHKeys();
    } catch (error) {
        console.error('[SSH Keys] Error deleting key:', error);
        Portal.toast(error.message || 'Failed to delete SSH key', 'error');
    }
}

/**
 * Format date string
 */
function formatDate(dateStr) {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Escape HTML (use shared version if available)
 */
if (typeof escapeHtml !== 'function') {
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}
