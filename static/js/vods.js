/**
 * Portal Gateway - VOD Manager
 * Handles remote SFTP VOD file browsing, download, and deletion.
 */

let vodsLoaded = false;

/**
 * Load VODs from remote SFTP storage
 */
async function loadVods() {
    const noStorage = document.getElementById('vods-no-storage');
    const loading = document.getElementById('vods-loading');
    const tableContainer = document.getElementById('vods-table-container');
    const empty = document.getElementById('vods-empty');
    const error = document.getElementById('vods-error');

    if (!noStorage) return;

    // Show loading
    noStorage.style.display = 'none';
    loading.style.display = 'flex';
    tableContainer.style.display = 'none';
    empty.style.display = 'none';
    error.style.display = 'none';

    try {
        const response = await fetch('/api/vods', { credentials: 'include' });

        if (response.status === 404) {
            // No storage configured
            loading.style.display = 'none';
            noStorage.style.display = 'flex';
            return;
        }

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to load VODs');
        }

        const data = await response.json();
        const files = data.files || [];

        loading.style.display = 'none';
        vodsLoaded = true;

        if (files.length === 0) {
            empty.style.display = 'flex';
            return;
        }

        tableContainer.style.display = 'block';
        const tbody = document.getElementById('vods-tbody');
        tbody.innerHTML = files.map(renderVodRow).join('');

    } catch (err) {
        console.error('Failed to load VODs:', err);
        loading.style.display = 'none';
        error.style.display = 'flex';
        document.getElementById('vods-error-message').textContent = err.message;
    }
}

/**
 * Render a single VOD table row
 */
function renderVodRow(file) {
    const size = Portal.formatBytes(file.size);
    const modified = file.modified ? formatVodDate(file.modified) : '--';
    const safeName = escapeHtml(file.name);
    const encodedName = encodeURIComponent(file.name);

    return `<tr>
        <td>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="16" height="16" style="color: var(--accent-blue); flex-shrink: 0;">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 4v16M17 4v16M3 8h4m10 0h4M3 12h18M3 16h4m10 0h4M4 20h16a1 1 0 001-1V5a1 1 0 00-1-1H4a1 1 0 00-1 1v14a1 1 0 001 1z" />
                </svg>
                <span style="word-break: break-all;">${safeName}</span>
            </div>
        </td>
        <td style="white-space: nowrap;">${size}</td>
        <td style="white-space: nowrap;">${modified}</td>
        <td style="white-space: nowrap;">
            <button class="btn btn-sm btn-primary" onclick="downloadVod('${encodedName}')">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download
            </button>
            <button class="btn btn-sm btn-danger" onclick="deleteVod('${encodedName}', '${safeName}')">Delete</button>
        </td>
    </tr>`;
}

/**
 * Format a UNIX timestamp to a readable date
 */
function formatVodDate(timestamp) {
    const date = new Date(timestamp * 1000);
    const now = new Date();
    const diffMs = now - date;
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
        return 'Today ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diffDays === 1) {
        return 'Yesterday ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diffDays < 7) {
        return diffDays + ' days ago';
    } else {
        return date.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
    }
}

/**
 * Download a VOD file
 */
function downloadVod(encodedFilename) {
    window.location.href = `/api/vods/download/${encodedFilename}`;
}

/**
 * Delete a VOD file
 */
async function deleteVod(encodedFilename, displayName) {
    if (!confirm(`Delete "${displayName}"? This cannot be undone.`)) return;

    try {
        const response = await fetch(`/api/vods/${encodedFilename}`, {
            method: 'DELETE',
            credentials: 'include'
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || 'Failed to delete VOD');
            return;
        }

        loadVods();
    } catch (err) {
        console.error('Failed to delete VOD:', err);
        alert('Failed to delete VOD');
    }
}

/**
 * Show the VOD storage settings modal
 */
async function showVodStorageModal() {
    // Reset form
    document.getElementById('vod-host').value = '';
    document.getElementById('vod-port').value = '22';
    document.getElementById('vod-username').value = '';
    document.getElementById('vod-auth-method').value = 'password';
    document.getElementById('vod-password').value = '';
    document.getElementById('vod-private-key').value = '';
    document.getElementById('vod-remote-path').value = '/home/user/vods';
    document.getElementById('vod-test-result').style.display = 'none';
    document.getElementById('vod-delete-btn').style.display = 'none';
    onVodAuthMethodChange();

    // Load existing config
    try {
        const response = await fetch('/api/vods/storage', { credentials: 'include' });
        const data = await response.json();

        if (data.storage) {
            const s = data.storage;
            document.getElementById('vod-host').value = s.host || '';
            document.getElementById('vod-port').value = s.port || 22;
            document.getElementById('vod-username').value = s.username || '';
            document.getElementById('vod-auth-method').value = s.auth_method || 'password';
            document.getElementById('vod-remote-path').value = s.remote_path || '';

            if (s.has_password) {
                document.getElementById('vod-password').value = '***';
            }
            if (s.has_key) {
                document.getElementById('vod-private-key').value = '***';
            }

            document.getElementById('vod-delete-btn').style.display = 'inline-flex';
            onVodAuthMethodChange();
        }
    } catch (err) {
        console.error('Failed to load VOD storage config:', err);
    }

    showModal('vod-storage-modal');
}

/**
 * Save VOD storage settings
 */
async function saveVodStorage(event) {
    event.preventDefault();

    const data = {
        host: document.getElementById('vod-host').value.trim(),
        port: parseInt(document.getElementById('vod-port').value) || 22,
        username: document.getElementById('vod-username').value.trim(),
        auth_method: document.getElementById('vod-auth-method').value,
        remote_path: document.getElementById('vod-remote-path').value.trim(),
    };

    if (data.auth_method === 'password') {
        data.password = document.getElementById('vod-password').value;
    } else {
        data.private_key = document.getElementById('vod-private-key').value;
    }

    try {
        const response = await fetch('/api/vods/storage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (!response.ok) {
            alert(result.error || 'Failed to save storage config');
            return;
        }

        closeModal('vod-storage-modal');
        loadVods();
    } catch (err) {
        console.error('Failed to save VOD storage:', err);
        alert('Failed to save storage config');
    }
}

/**
 * Delete VOD storage config
 */
async function deleteVodStorage() {
    if (!confirm('Remove VOD storage configuration? This will not delete any remote files.')) return;

    try {
        const response = await fetch('/api/vods/storage', {
            method: 'DELETE',
            credentials: 'include'
        });

        if (!response.ok) {
            const data = await response.json();
            alert(data.error || 'Failed to delete storage config');
            return;
        }

        closeModal('vod-storage-modal');
        loadVods();
    } catch (err) {
        console.error('Failed to delete VOD storage:', err);
        alert('Failed to delete storage config');
    }
}

/**
 * Test SFTP connection with current form values
 */
async function testVodConnection() {
    const btn = document.getElementById('vod-test-btn');
    const resultEl = document.getElementById('vod-test-result');
    const origText = btn.textContent;
    btn.textContent = 'Testing...';
    btn.disabled = true;
    resultEl.style.display = 'none';

    const data = {
        host: document.getElementById('vod-host').value.trim(),
        port: parseInt(document.getElementById('vod-port').value) || 22,
        username: document.getElementById('vod-username').value.trim(),
        auth_method: document.getElementById('vod-auth-method').value,
        remote_path: document.getElementById('vod-remote-path').value.trim(),
    };

    if (data.auth_method === 'password') {
        data.password = document.getElementById('vod-password').value;
    } else {
        data.private_key = document.getElementById('vod-private-key').value;
    }

    try {
        const response = await fetch('/api/vods/storage/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(data)
        });

        const result = await response.json();

        resultEl.style.display = 'block';
        if (result.success) {
            resultEl.style.background = 'rgba(34, 197, 94, 0.1)';
            resultEl.style.border = '1px solid rgba(34, 197, 94, 0.3)';
            resultEl.style.color = '#22c55e';
            resultEl.textContent = result.message;
        } else {
            resultEl.style.background = 'rgba(239, 68, 68, 0.1)';
            resultEl.style.border = '1px solid rgba(239, 68, 68, 0.3)';
            resultEl.style.color = '#ef4444';
            resultEl.textContent = result.error || 'Connection failed';
        }
    } catch (err) {
        resultEl.style.display = 'block';
        resultEl.style.background = 'rgba(239, 68, 68, 0.1)';
        resultEl.style.border = '1px solid rgba(239, 68, 68, 0.3)';
        resultEl.style.color = '#ef4444';
        resultEl.textContent = 'Network error';
    } finally {
        btn.textContent = origText;
        btn.disabled = false;
    }
}

/**
 * Toggle auth method fields visibility
 */
function onVodAuthMethodChange() {
    const method = document.getElementById('vod-auth-method').value;
    document.getElementById('vod-password-field').style.display = method === 'password' ? 'block' : 'none';
    document.getElementById('vod-key-field').style.display = method === 'key' ? 'block' : 'none';
}
