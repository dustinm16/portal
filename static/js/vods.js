/**
 * Open Relay Portal - VOD Manager
 * Session-grouped browsing with search, multi-select, and archive download.
 */

let vodsLoaded = false;
let vodFiles = [];        // raw file list from API
let vodSelected = new Set(); // selected file paths

/**
 * Load VODs from remote SFTP storage
 */
async function loadVods() {
    const noStorage = document.getElementById('vods-no-storage');
    const loading = document.getElementById('vods-loading');
    const container = document.getElementById('vods-table-container');
    const toolbar = document.getElementById('vods-toolbar');
    const empty = document.getElementById('vods-empty');
    const error = document.getElementById('vods-error');

    if (!noStorage) return;

    noStorage.style.display = 'none';
    loading.style.display = 'flex';
    container.style.display = 'none';
    if (toolbar) toolbar.style.display = 'none';
    empty.style.display = 'none';
    error.style.display = 'none';

    try {
        const response = await fetch('/api/vods', { credentials: 'include' });

        if (response.status === 404) {
            loading.style.display = 'none';
            noStorage.style.display = 'flex';
            return;
        }

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to load VODs');
        }

        const data = await response.json();
        vodFiles = data.files || [];
        vodSelected.clear();
        vodsLoaded = true;
        loading.style.display = 'none';

        if (vodFiles.length === 0) {
            empty.style.display = 'flex';
            return;
        }

        if (toolbar) toolbar.style.display = 'block';
        container.style.display = 'block';
        renderVods(vodFiles);
        updateSelectionUI();

    } catch (err) {
        console.error('Failed to load VODs:', err);
        loading.style.display = 'none';
        error.style.display = 'flex';
        document.getElementById('vods-error-message').textContent = err.message;
    }
}

/**
 * Group files into sessions by directory path.
 * Files in root (no directory) get grouped as "Ungrouped".
 */
function groupBySession(files) {
    const sessions = {};
    for (const file of files) {
        const parts = file.name.split('/');
        let sessionKey, displayLabel;
        if (parts.length >= 3) {
            // StreamName/session_timestamp/chunk.mkv
            sessionKey = parts.slice(0, -1).join('/');
            displayLabel = parts.slice(0, -1).join(' / ');
        } else if (parts.length === 2) {
            // StreamName/file.mkv
            sessionKey = parts[0];
            displayLabel = parts[0];
        } else {
            sessionKey = '';
            displayLabel = 'Standalone Files';
        }
        if (!sessions[sessionKey]) {
            sessions[sessionKey] = { label: displayLabel, key: sessionKey, files: [] };
        }
        sessions[sessionKey].files.push(file);
    }
    // Sort sessions: newest first by latest file modified time
    return Object.values(sessions).sort((a, b) => {
        const aMax = Math.max(...a.files.map(f => f.modified || 0));
        const bMax = Math.max(...b.files.map(f => f.modified || 0));
        return bMax - aMax;
    });
}

/**
 * Render VOD sessions into the container.
 */
function renderVods(files) {
    const container = document.getElementById('vods-table-container');
    const sessions = groupBySession(files);

    let html = '';
    for (const session of sessions) {
        const totalSize = session.files.reduce((sum, f) => sum + (f.size || 0), 0);
        const chunkCount = session.files.length;
        const latestMod = Math.max(...session.files.map(f => f.modified || 0));
        const sessionId = CSS.escape(session.key || '_root');

        // Check if all files in session are selected
        const allSelected = session.files.every(f => vodSelected.has(f.name));
        const someSelected = !allSelected && session.files.some(f => vodSelected.has(f.name));

        html += `<div class="vod-session" data-session="${escapeHtml(session.key)}">
            <div class="vod-session-header" onclick="toggleVodSession(this)">
                <div style="display: flex; align-items: center; gap: 0.75rem; flex: 1; min-width: 0;">
                    <input type="checkbox" class="vod-session-checkbox"
                        onclick="toggleSessionSelect(event, '${escapeHtml(session.key)}')"
                        ${allSelected ? 'checked' : ''} ${someSelected ? 'indeterminate' : ''}>
                    <span class="vod-session-arrow">&#9660;</span>
                    <div style="min-width: 0;">
                        <div class="vod-session-title">${escapeHtml(session.label)}</div>
                        <div class="vod-session-meta">
                            ${chunkCount} chunk${chunkCount !== 1 ? 's' : ''}
                            &middot; ${Portal.formatBytes(totalSize)}
                            &middot; ${formatVodDate(latestMod)}
                        </div>
                    </div>
                </div>
                <div class="vod-session-actions" onclick="event.stopPropagation()">
                    <button class="btn btn-sm btn-primary" onclick="downloadSession('${escapeHtml(session.key)}')" title="Download session as .zip">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteSession('${escapeHtml(session.key)}')" title="Delete session">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                </div>
            </div>
            <div class="vod-session-files">`;

        for (const file of session.files) {
            const basename = file.name.split('/').pop();
            const encodedName = file.name.split('/').map(encodeURIComponent).join('/');
            const isSelected = vodSelected.has(file.name);

            html += `<div class="vod-file-row ${isSelected ? 'selected' : ''}" data-name="${escapeHtml(file.name)}">
                <input type="checkbox" class="vod-file-checkbox"
                    onclick="toggleFileSelect(event, '${escapeHtml(file.name)}')" ${isSelected ? 'checked' : ''}>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14" style="color: var(--accent-blue); flex-shrink: 0;">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 4v16M17 4v16M3 8h4m10 0h4M3 12h18M3 16h4m10 0h4M4 20h16a1 1 0 001-1V5a1 1 0 00-1-1H4a1 1 0 00-1 1v14a1 1 0 001 1z" />
                </svg>
                <span class="vod-file-name">${escapeHtml(basename)}</span>
                <span class="vod-file-size">${Portal.formatBytes(file.size)}</span>
                <span class="vod-file-date">${formatVodDate(file.modified)}</span>
                <div class="vod-file-actions">
                    <button class="btn btn-sm btn-primary" onclick="downloadVod('${encodedName}')" title="Download">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="12" height="12"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteVod('${encodedName}', '${escapeHtml(basename)}')" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="12" height="12"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                </div>
            </div>`;
        }

        html += `</div></div>`;
    }

    container.innerHTML = html;

    // Fix indeterminate state (can't set via HTML attribute)
    container.querySelectorAll('.vod-session').forEach(el => {
        const key = el.dataset.session;
        const sessionFiles = vodFiles.filter(f => {
            const parts = f.name.split('/');
            const sk = parts.length >= 3 ? parts.slice(0, -1).join('/') :
                       parts.length === 2 ? parts[0] : '';
            return sk === key;
        });
        const allSel = sessionFiles.every(f => vodSelected.has(f.name));
        const someSel = !allSel && sessionFiles.some(f => vodSelected.has(f.name));
        const cb = el.querySelector('.vod-session-checkbox');
        if (cb) cb.indeterminate = someSel;
    });
}

/**
 * Toggle session expand/collapse
 */
function toggleVodSession(header) {
    const session = header.closest('.vod-session');
    session.classList.toggle('collapsed');
}

/**
 * Select/deselect all files in a session
 */
function toggleSessionSelect(event, sessionKey) {
    event.stopPropagation();
    const files = getSessionFiles(sessionKey);
    const allSelected = files.every(f => vodSelected.has(f.name));
    files.forEach(f => {
        if (allSelected) vodSelected.delete(f.name);
        else vodSelected.add(f.name);
    });
    renderVods(getFilteredFiles());
    updateSelectionUI();
}

/**
 * Select/deselect a single file
 */
function toggleFileSelect(event, fileName) {
    event.stopPropagation();
    if (vodSelected.has(fileName)) vodSelected.delete(fileName);
    else vodSelected.add(fileName);
    renderVods(getFilteredFiles());
    updateSelectionUI();
}

/**
 * Get files belonging to a session key
 */
function getSessionFiles(sessionKey) {
    return vodFiles.filter(f => {
        const parts = f.name.split('/');
        const sk = parts.length >= 3 ? parts.slice(0, -1).join('/') :
                   parts.length === 2 ? parts[0] : '';
        return sk === sessionKey;
    });
}

/**
 * Update selection count and button visibility
 */
function updateSelectionUI() {
    const count = vodSelected.size;
    const countEl = document.getElementById('vods-selection-count');
    const dlBtn = document.getElementById('vods-download-selected');
    const delBtn = document.getElementById('vods-delete-selected');

    if (countEl) {
        countEl.textContent = `${count} selected`;
        countEl.style.display = count > 0 ? 'inline' : 'none';
    }
    if (dlBtn) dlBtn.style.display = count > 0 ? 'inline-flex' : 'none';
    if (delBtn) delBtn.style.display = count > 1 ? 'inline-flex' : 'none';
}

/**
 * Search/filter VODs
 */
function filterVods() {
    const filtered = getFilteredFiles();
    if (filtered.length === 0) {
        document.getElementById('vods-table-container').innerHTML =
            '<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No VODs match your search.</div>';
    } else {
        renderVods(filtered);
    }
}

function getFilteredFiles() {
    const searchEl = document.getElementById('vods-search');
    const term = (searchEl ? searchEl.value : '').toLowerCase().trim();
    if (!term) return vodFiles;
    return vodFiles.filter(f => f.name.toLowerCase().includes(term));
}

/**
 * Download selected VODs as zip archive
 */
async function downloadSelectedVods() {
    const files = Array.from(vodSelected);
    if (files.length === 0) return;
    if (files.length === 1) {
        // Single file — direct download
        downloadVod(files[0].split('/').map(encodeURIComponent).join('/'));
        return;
    }
    await downloadArchive(files);
}

/**
 * Download all files in a session as zip
 */
async function downloadSession(sessionKey) {
    const files = getSessionFiles(sessionKey).map(f => f.name);
    if (files.length === 0) return;
    if (files.length === 1) {
        downloadVod(files[0].split('/').map(encodeURIComponent).join('/'));
        return;
    }
    await downloadArchive(files);
}

/**
 * Request zip archive from server and trigger browser download
 */
async function downloadArchive(files) {
    try {
        const response = await fetch('/api/vods/download-archive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ files })
        });

        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            alert(data.error || 'Failed to create archive');
            return;
        }

        const blob = await response.blob();
        const disposition = response.headers.get('Content-Disposition') || '';
        const match = disposition.match(/filename="(.+?)"/);
        const filename = match ? match[1] : 'vods.zip';

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (err) {
        console.error('Archive download failed:', err);
        alert('Failed to download archive');
    }
}

/**
 * Delete all files in a session
 */
async function deleteSession(sessionKey) {
    const files = getSessionFiles(sessionKey);
    if (files.length === 0) return;
    const label = sessionKey || 'these files';
    if (!confirm(`Delete ${files.length} file(s) in "${label}"? This cannot be undone.`)) return;

    let errors = 0;
    for (const file of files) {
        try {
            const encoded = file.name.split('/').map(encodeURIComponent).join('/');
            const response = await fetch(`/api/vods/${encoded}`, {
                method: 'DELETE', credentials: 'include'
            });
            if (!response.ok) errors++;
        } catch { errors++; }
    }
    if (errors > 0) alert(`${errors} file(s) could not be deleted.`);
    loadVods();
}

/**
 * Delete all selected files
 */
async function deleteSelectedVods() {
    const files = Array.from(vodSelected);
    if (files.length === 0) return;
    if (!confirm(`Delete ${files.length} selected file(s)? This cannot be undone.`)) return;

    let errors = 0;
    for (const name of files) {
        try {
            const encoded = name.split('/').map(encodeURIComponent).join('/');
            const response = await fetch(`/api/vods/${encoded}`, {
                method: 'DELETE', credentials: 'include'
            });
            if (!response.ok) errors++;
        } catch { errors++; }
    }
    if (errors > 0) alert(`${errors} file(s) could not be deleted.`);
    vodSelected.clear();
    loadVods();
}

/**
 * Download a single VOD file
 */
function downloadVod(encodedFilename) {
    window.location.href = `/api/vods/download/${encodedFilename}`;
}

/**
 * Delete a single VOD file
 */
async function deleteVod(encodedFilename, displayName) {
    if (!confirm(`Delete "${displayName}"? This cannot be undone.`)) return;
    try {
        const response = await fetch(`/api/vods/${encodedFilename}`, {
            method: 'DELETE', credentials: 'include'
        });
        const data = await response.json();
        if (!response.ok) { alert(data.error || 'Failed to delete VOD'); return; }
        loadVods();
    } catch (err) {
        console.error('Failed to delete VOD:', err);
        alert('Failed to delete VOD');
    }
}

/**
 * Format UNIX timestamp to readable date
 */
function formatVodDate(timestamp) {
    if (!timestamp) return '--';
    const date = new Date(timestamp * 1000);
    const now = new Date();
    const diffDays = Math.floor((now - date) / (1000 * 60 * 60 * 24));
    if (diffDays === 0) return 'Today ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diffDays === 1) return 'Yesterday ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diffDays < 7) return diffDays + ' days ago';
    return date.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
}

// ── VOD Storage Modal (unchanged) ──

async function showVodStorageModal() {
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
            if (s.has_password) document.getElementById('vod-password').value = '***';
            if (s.has_key) document.getElementById('vod-private-key').value = '***';
            document.getElementById('vod-delete-btn').style.display = 'inline-flex';
            onVodAuthMethodChange();
        }
    } catch (err) { console.error('Failed to load VOD storage config:', err); }

    showModal('vod-storage-modal');
}

async function saveVodStorage(event) {
    event.preventDefault();
    const data = {
        host: document.getElementById('vod-host').value.trim(),
        port: parseInt(document.getElementById('vod-port').value) || 22,
        username: document.getElementById('vod-username').value.trim(),
        auth_method: document.getElementById('vod-auth-method').value,
        remote_path: document.getElementById('vod-remote-path').value.trim(),
    };
    if (data.auth_method === 'password') data.password = document.getElementById('vod-password').value;
    else data.private_key = document.getElementById('vod-private-key').value;

    try {
        const response = await fetch('/api/vods/storage', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            credentials: 'include', body: JSON.stringify(data)
        });
        const result = await response.json();
        if (!response.ok) { alert(result.error || 'Failed to save storage config'); return; }
        closeModal('vod-storage-modal');
        loadVods();
    } catch (err) { alert('Failed to save storage config'); }
}

async function deleteVodStorage() {
    if (!confirm('Remove VOD storage configuration? This will not delete any remote files.')) return;
    try {
        const response = await fetch('/api/vods/storage', { method: 'DELETE', credentials: 'include' });
        if (!response.ok) { const d = await response.json(); alert(d.error || 'Failed'); return; }
        closeModal('vod-storage-modal');
        loadVods();
    } catch (err) { alert('Failed to delete storage config'); }
}

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
    if (data.auth_method === 'password') data.password = document.getElementById('vod-password').value;
    else data.private_key = document.getElementById('vod-private-key').value;

    try {
        const response = await fetch('/api/vods/storage/test', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            credentials: 'include', body: JSON.stringify(data)
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
    } catch {
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

function onVodAuthMethodChange() {
    const method = document.getElementById('vod-auth-method').value;
    document.getElementById('vod-password-field').style.display = method === 'password' ? 'block' : 'none';
    document.getElementById('vod-key-field').style.display = method === 'key' ? 'block' : 'none';
}
