/**
 * Open Relay Portal - Dashboard
 */

let services = [];
let currentCategory = 'all';
var currentUser = null;  // shared with admin.js
let _gsByServiceId = {};  // service_id -> game_server row (build info for the card badge)

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    await loadUserInfo();
    await loadServices();
    await loadDashboardStats();
    await loadActivityFeed();
    await loadSearchNavLink();
    initDashSearch();
});

/**
 * Show the "Search" nav link only when the SearXNG managed service is enabled
 * and running. The portal is fully functional whether or not it is.
 */
async function loadSearchNavLink() {
    const link = document.getElementById('search-nav-link');
    if (!link) return;
    try {
        const { available } = await Portal.api('/api/search/status');
        link.style.display = available ? '' : 'none';
    } catch (e) {
        link.style.display = 'none';
    }
}

/**
 * Dashboard search bar. "Portal" mode searches the portal's indexed messages
 * (opens the chat search); "Internet" mode runs a private web search via the
 * SearXNG managed service, and only appears when that service is available.
 */
async function initDashSearch() {
    const form = document.getElementById('dash-search');
    if (!form) return;
    const input = document.getElementById('dash-search-input');
    const modeBtns = form.querySelectorAll('.dash-search-mode');
    const internetBtn = form.querySelector('[data-mode="internet"]');

    const PLACEHOLDERS = {
        portal: 'Search messages, files and channels…',
        internet: 'Search the web privately…',
    };

    let mode = localStorage.getItem('dash-search-mode') || 'portal';

    // The Internet option only exists when SearXNG is enabled + running.
    let internetAvailable = false;
    try {
        internetAvailable = (await Portal.api('/api/search/status')).available;
    } catch (e) { /* leave false */ }
    if (internetAvailable) {
        internetBtn.hidden = false;
    } else if (mode === 'internet') {
        mode = 'portal';
    }

    function setMode(next) {
        mode = next;
        localStorage.setItem('dash-search-mode', next);
        modeBtns.forEach(b => b.classList.toggle('active', b.dataset.mode === next));
        input.placeholder = PLACEHOLDERS[next] || PLACEHOLDERS.portal;
    }
    setMode(mode);

    modeBtns.forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const q = input.value.trim();
        if (!q) return;
        if (mode === 'internet' && internetAvailable) {
            window.location.href = '/search/search?q=' + encodeURIComponent(q);
        } else {
            window.location.href = '/chat?q=' + encodeURIComponent(q);
        }
    });
}

/**
 * Load current user info
 */
async function loadUserInfo() {
    try {
        currentUser = await Portal.getCurrentUser();

        // Set username in navbar
        document.getElementById('username').textContent = currentUser.username;

        // Role labels
        const roleLabels = {
            'superadmin': 'Super Admin',
            'admin': 'Admin',
            'moderator': 'Moderator',
            'user': 'User'
        };

        // Show admin badge and section based on role
        const role = currentUser.role || 'user';
        const canManageUsers = currentUser.permissions?.can_manage_users;

        if (Portal.isAdmin(currentUser)) {
            const adminBadge = document.getElementById('admin-badge');
            const terminalBtn = document.getElementById('terminal-btn');

            if (adminBadge) {
                adminBadge.style.display = 'inline-block';
                adminBadge.textContent = role === 'superadmin' ? 'Super Admin' : 'Admin';
            }
            if (terminalBtn) terminalBtn.style.display = 'flex';
        }

        // The Administration sidebar shows for moderator+ , but only "Manage
        // Users" actually works below admin — Invite Code, View Logs and the
        // Admin Panel link are all admin-only (403 / bounce), so hide those
        // for a non-admin so they only see what they can use.
        if (canManageUsers) {
            const adminSection = document.getElementById('admin-section');
            if (adminSection) adminSection.style.display = 'block';
            if (!Portal.isAdmin(currentUser)) {
                ['nav-invite-code', 'nav-view-logs', 'nav-admin-panel'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.style.display = 'none';
                });
            }
        }

        // The Services tab is admin-only — unless the user has been granted
        // control/logs on a specific service, in which case they need it to
        // reach that one service.
        const hasServiceGrants = currentUser.granted_services
            && Object.keys(currentUser.granted_services).length > 0;
        if (!Portal.isAdmin(currentUser) && !hasServiceGrants) {
            const servicesTab = document.getElementById('tab-btn-services');
            if (servicesTab) servicesTab.style.display = 'none';
            // Switch to My Connections as default tab for regular users
            switchTab('my-connections');
        } else if (!Portal.isAdmin(currentUser)) {
            // Granted non-admin: keep the tab but default to My Connections.
            switchTab('my-connections');
        }

        // Set profile modal info
        const profileUsername = document.getElementById('profile-username');
        const profileRole = document.getElementById('profile-role');
        if (profileUsername) profileUsername.textContent = currentUser.username;
        if (profileRole) profileRole.textContent = roleLabels[role] || 'User';

        // Hide add connection / stream UI when disabled by admin
        if (currentUser.permissions) {
            if (!currentUser.permissions.can_add_connections) {
                const addConnBtn = document.getElementById('add-connection-btn');
                const quickAddBar = document.getElementById('quick-add-bar');
                if (addConnBtn) addConnBtn.style.display = 'none';
                if (quickAddBar) quickAddBar.style.display = 'none';
            }
            if (!currentUser.permissions.can_add_streams) {
                const addStreamBtn = document.getElementById('add-stream-btn');
                if (addStreamBtn) addStreamBtn.style.display = 'none';
            }
        }

    } catch (error) {
        console.error('Failed to load user info:', error);
        Portal.toast('Failed to load user info', 'error');
    }
}

/**
 * Load and display services
 */
async function loadServices() {
    const loading = document.getElementById('loading');
    const grid = document.getElementById('services-grid');
    const emptyState = document.getElementById('empty-state');

    loading.style.display = 'flex';
    grid.style.display = 'none';
    emptyState.style.display = 'none';

    try {
        services = await Portal.getServices();
        // Game-server rows carry the build info (installed vs latest) that
        // drives the "up to date / update available" badge on the card.
        try {
            const gs = (await Portal.fetchJSON('/api/game-servers')).game_servers || [];
            _gsByServiceId = {};
            gs.forEach(g => { if (g.service_id) _gsByServiceId[g.service_id] = g; });
        } catch (e) { _gsByServiceId = {}; }
        renderServices();
    } catch (error) {
        console.error('Failed to load services:', error);
        Portal.toast('Failed to load services', 'error');
    } finally {
        loading.style.display = 'none';
    }
}

/**
 * Refresh all dashboard resources (connections, streams, stats, services)
 */
async function refreshResources() {
    const promises = [
        loadInlineConnections(),
        loadUserStreams(),
        loadDashboardStats()
    ];
    if (typeof loadServices === 'function') {
        promises.push(loadServices());
    }
    await Promise.all(promises);
    Portal.toast('Resources refreshed');
}

/**
 * Refresh services list (legacy alias)
 */
async function refreshServices() {
    await refreshResources();
}

/**
 * Render services grid
 */
function renderServices() {
    const grid = document.getElementById('services-grid');
    const emptyState = document.getElementById('empty-state');

    // Filter by category if needed
    let filteredServices = services;
    if (currentCategory !== 'all') {
        filteredServices = services.filter(s => s.category_id === currentCategory);
    }

    const isAdmin = Portal.isAdmin(currentUser);
    const grantOn = (s) => {
        const g = currentUser && currentUser.granted_services && currentUser.granted_services[s.id];
        return !!(g && g.length);
    };

    // A non-admin only reaches this tab because they hold a service grant —
    // show them just the service(s) they were granted, nothing else.
    if (!isAdmin) {
        filteredServices = filteredServices.filter(grantOn);
    }

    // Hide disabled services — but a managed service that's disabled just means
    // "don't auto-start on Portal boot" (common for a systemd-wrapped game
    // server that already runs on its own), so still show it to an admin or to
    // a user who's been granted control/logs on it.
    filteredServices = filteredServices.filter(s => s.enabled !== false || isAdmin || grantOn(s));

    if (filteredServices.length === 0) {
        grid.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }

    grid.style.display = 'grid';
    emptyState.style.display = 'none';

    grid.innerHTML = filteredServices.map(service => createServiceCard(service)).join('');

    // Add click handlers
    grid.querySelectorAll('.service-card').forEach(card => {
        card.addEventListener('click', () => {
            const serviceId = card.dataset.serviceId;
            const service = services.find(s => s.id == serviceId);
            if (!service) return;
            // A game server the viewer can browse opens the commander-style
            // file browser directly, same as clicking its card in the admin
            // Game Servers tab. Everyone else keeps the usual service-details
            // view (the "Files" action button still works either way).
            const grant = (currentUser && currentUser.granted_services && currentUser.granted_services[service.id]) || [];
            const canFiles = Portal.isAdmin(currentUser) || grant.includes('files');
            if (service.plugin === 'gameserver' && canFiles) {
                showGameServerFiles(service.id, service.display_name || service.name);
                return;
            }
            Portal.openService(service);
        });
    });
}

/**
 * Create service card HTML
 */
function createServiceCard(service) {
    const plugin = service.plugin || 'tcp_tunnel';
    const icon = Portal.getServiceIcon(plugin);
    const pluginName = Portal.getPluginDisplayName(plugin);
    const isAdmin = Portal.isAdmin(currentUser);
    const isManaged = service.service_type === 'managed';
    const hasProcessControl = isManaged || !!service.systemd_unit;
    const grant = (currentUser && currentUser.granted_services && currentUser.granted_services[service.id]) || [];
    const canControl = isAdmin || grant.includes('control');
    const canLogs = isAdmin || grant.includes('logs');
    const canFiles = isAdmin || grant.includes('files');
    const isGameServer = plugin === 'gameserver';
    const gsInfo = isGameServer ? _gsByServiceId[service.id] : null;
    const gsUpdateAvail = !!(gsInfo && gsInfo.installed_build && gsInfo.latest_build
        && String(gsInfo.installed_build) !== String(gsInfo.latest_build));

    // Every action the viewer is permitted to take on this service, rendered
    // as a clearly-labelled button row at the foot of the card — admins and
    // users holding a matching grant. Editing / deleting / creating a service
    // still lives in the Admin panel > Managed Services tab.
    const nameEsc = escapeHtml(service.display_name || service.name).replace(/'/g, "\\'");
    const acts = [];
    if (hasProcessControl && canControl) {
        if (service.status === 'running') {
            acts.push(`<button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); stopService(${service.id})">Stop</button>`);
            acts.push(`<button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); restartService(${service.id})">Restart</button>`);
        } else {
            acts.push(`<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); startService(${service.id})">Start</button>`);
        }
    }
    if (isManaged && canLogs) {
        acts.push(`<button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showServiceLogs(${service.id}, '${nameEsc}')">Logs</button>`);
    }
    if (isGameServer && canControl && gsInfo) {
        acts.push(`<button class="btn btn-sm ${gsUpdateAvail ? 'btn-primary' : 'btn-secondary'}" onclick="event.stopPropagation(); gsCardUpdate(${service.id}, '${nameEsc}')">Update</button>`);
        acts.push(`<button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); openGsLaunch(${service.id}, '${nameEsc}')">Options</button>`);
    }
    if (isGameServer && canFiles) {
        acts.push(`<button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showGameServerFiles(${service.id}, '${nameEsc}')">Files</button>`);
        acts.push(`<button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); gsCardBackup(${service.id}, '${nameEsc}')">Backup</button>`);
    }
    const actionRow = acts.length
        ? `<div class="service-actions" style="display:flex;flex-wrap:wrap;gap:0.4rem;margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--card-border);">${acts.join('')}</div>`
        : '';

    // Determine status display
    let statusClass = 'online';
    let statusText = 'Available';
    if (isManaged) {
        if (service.status === 'running') {
            statusClass = 'online';
            statusText = 'Running';
        } else if (service.status === 'error') {
            statusClass = 'offline';
            statusText = 'Error';
        } else {
            statusClass = 'offline';
            statusText = 'Stopped';
        }
    }

    // Type badge for service type
    const typeBadge = isManaged
        ? `<span class="service-type-badge managed">Managed</span>`
        : `<span class="service-type-badge proxy">Proxy</span>`;

    // Game-server build status, shown next to the run status.
    let updateChip = '';
    if (gsInfo) {
        const ib = gsInfo.installed_build, lb = gsInfo.latest_build;
        const pill = 'font-size:0.7rem;font-weight:600;padding:0.2rem 0.55rem;border-radius:9999px;';
        if (gsUpdateAvail) {
            updateChip = `<span title="installed ${escapeHtml(String(ib))} → latest ${escapeHtml(String(lb))}" style="${pill}background:rgba(var(--accent-yellow-rgb,234,179,8),0.18);color:var(--accent-yellow);">● Update available</span>`;
        } else if (ib && lb) {
            updateChip = `<span title="build ${escapeHtml(String(ib))}" style="${pill}background:rgba(var(--accent-green-rgb,34,197,94),0.16);color:var(--accent-green);">✓ Up to date</span>`;
        } else {
            updateChip = `<span title="build not checked yet — a background check runs every 6 h" style="${pill}background:var(--code-bg);color:var(--text-muted);">· checking…</span>`;
        }
    }

    return `
        <div class="service-card" data-service-id="${service.id}">
            <div class="service-card-header">
                <div class="service-icon">
                    ${icon}
                </div>
                <div class="service-info">
                    <div class="service-name">${escapeHtml(service.display_name || service.name)} ${typeBadge}</div>
                    <div class="service-plugin">${pluginName}</div>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                <div class="service-status ${statusClass}">
                    <span class="service-status-dot"></span>
                    ${statusText}
                </div>
                ${updateChip}
            </div>
            ${actionRow}
        </div>
    `;
}

/**
 * Download a game-server backup straight from its dashboard card.
 */
async function gsCardBackup(serviceId, name) {
    Portal.toast('Preparing backup…');
    try {
        const servers = (await Portal.fetchJSON('/api/game-servers')).game_servers || [];
        const gs = servers.find(s => s.service_id === serviceId);
        if (!gs) { Portal.toast('Game server not found', 'error'); return; }
        const res = await Portal.fetch(`/api/game-servers/${gs.id}/config/download`);
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Backup failed');
        const blob = await res.blob();
        const m = (res.headers.get('Content-Disposition') || '').match(/filename="(.+?)"/);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = m ? m[1] : `${name}-backup.tar.gz`;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
    } catch (e) {
        Portal.toast(e.message || 'Backup failed', 'error');
    }
}

/**
 * Run a SteamCMD update on a game server from its dashboard card. No-ops
 * server-side if the build is already current; otherwise stops, updates and
 * restarts the server. Polls the job quietly and refreshes when it finishes.
 */
async function gsCardUpdate(serviceId, name) {
    const gs = _gsByServiceId[serviceId];
    if (!gs) { Portal.toast('Game server not found', 'error'); return; }
    if (!confirm(`Update "${name}" now? If a newer build exists the server will be stopped, updated and restarted.`)) return;
    try {
        const d = await Portal.fetchJSON(`/api/game-servers/${gs.id}/update`, { method: 'POST' });
        Portal.toast('Checking for a newer build…');
        if (!d.job_id) { setTimeout(loadServices, 2000); return; }
        let tries = 0;
        const poll = setInterval(async () => {
            if (++tries > 200) { clearInterval(poll); loadServices(); return; }  // ~10 min ceiling
            try {
                const j = await Portal.fetchJSON(`/api/game-servers/jobs/${d.job_id}`);
                if (j.status && j.status !== 'running') {
                    clearInterval(poll);
                    const log = (j.log || []).join(' ').toLowerCase();
                    let msg, kind = 'success';
                    if (j.status !== 'completed') { msg = `${name}: update ${j.status}`; kind = 'error'; }
                    // "nothing to do" is our own sentinel from _update_job's no-op
                    // path; "up to date" alone also appears in SteamCMD depot output.
                    else if (log.includes('nothing to do')) msg = `${name} is already up to date`;
                    else msg = `${name}: update finished`;
                    Portal.toast(msg, kind);
                    loadServices();
                }
            } catch (e) { clearInterval(poll); loadServices(); }
        }, 3000);
    } catch (e) {
        Portal.toast(e.message || 'Update failed to start', 'error');
    }
}

/**
 * Edit a game server's launch arguments / stop signal from its dashboard card.
 * `control` grant is enough (no shell is run on the args); the start command
 * is admin-only and hidden otherwise.
 */
let _gsLaunchSid = null;
function openGsLaunch(serviceId, name) {
    const gs = _gsByServiceId[serviceId];
    if (!gs) { Portal.toast('Game server not found', 'error'); return; }
    _gsLaunchSid = serviceId;
    document.getElementById('gs-launch-title').textContent = name;
    document.getElementById('gs-launch-args').value = gs.start_args || '';
    document.getElementById('gs-launch-signal').value = gs.stop_signal || 'SIGTERM';
    document.getElementById('gs-launch-cmd').value = gs.start_cmd || '';
    const isAdmin = Portal.isAdmin(currentUser);
    document.getElementById('gs-launch-cmd-row').style.display = isAdmin ? '' : 'none';
    document.getElementById('gs-launch-note').textContent = '';
    if (typeof showModal === 'function') showModal('gs-launch-modal');
    else document.getElementById('gs-launch-modal').style.display = 'flex';
}

async function saveGsLaunch() {
    if (!_gsLaunchSid) return;
    const gs = _gsByServiceId[_gsLaunchSid];
    if (!gs) return;
    const btn = document.getElementById('gs-launch-save');
    btn.disabled = true;
    try {
        const body = {
            start_args: document.getElementById('gs-launch-args').value,
            stop_signal: document.getElementById('gs-launch-signal').value,
        };
        if (Portal.isAdmin(currentUser)) {
            const c = document.getElementById('gs-launch-cmd').value.trim();
            if (c) body.start_cmd = c;
        }
        const res = await Portal.fetch(`/api/game-servers/${gs.id}/launch-options`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error || 'Save failed');
        Portal.toast('Launch options saved');
        if (d.restart_required) {
            document.getElementById('gs-launch-note').textContent =
                'Saved. Restart the server to apply the new options.';
        } else if (typeof closeModal === 'function') {
            closeModal('gs-launch-modal');
        } else {
            document.getElementById('gs-launch-modal').style.display = 'none';
        }
        loadServices();
    } catch (e) {
        Portal.toast(e.message || 'Save failed', 'error');
    } finally {
        btn.disabled = false;
    }
}

/**
 * Start a managed service
 */
async function startService(serviceId) {
    try {
        const data = await Portal.api(`/api/services/${serviceId}/start`, {
            method: 'POST'
        });
        if (data.success) {
            Portal.toast('Service started successfully');
            await loadServices();
        } else {
            Portal.toast(data.error || 'Failed to start service', 'error');
        }
    } catch (error) {
        console.error('Failed to start service:', error);
        Portal.toast('Failed to start service', 'error');
    }
}

/**
 * Stop a managed service
 */
async function stopService(serviceId) {
    try {
        const data = await Portal.api(`/api/services/${serviceId}/stop`, {
            method: 'POST'
        });
        if (data.success) {
            Portal.toast('Service stopped successfully');
            await loadServices();
        } else {
            Portal.toast(data.error || 'Failed to stop service', 'error');
        }
    } catch (error) {
        console.error('Failed to stop service:', error);
        Portal.toast('Failed to stop service', 'error');
    }
}

/**
 * Restart a managed service, or a service bound to a systemd unit
 */
async function restartService(serviceId) {
    try {
        const data = await Portal.api(`/api/services/${serviceId}/restart`, {
            method: 'POST'
        });
        if (data.success) {
            Portal.toast('Service restarted successfully');
            await loadServices();
        } else {
            Portal.toast(data.error || 'Failed to restart service', 'error');
        }
    } catch (error) {
        console.error('Failed to restart service:', error);
        Portal.toast('Failed to restart service', 'error');
    }
}

/**
 * View managed-service logs (admins + users with a 'logs' grant)
 */
async function showServiceLogs(serviceId, name) {
    document.getElementById('svc-logs-title').textContent = `Logs: ${name}`;
    const box = document.getElementById('svc-logs-content');
    box.innerHTML = '<div class="loading"><div class="spinner"></div> Loading…</div>';
    if (typeof showModal === 'function') showModal('svc-logs-modal');
    else document.getElementById('svc-logs-modal').style.display = 'flex';
    try {
        const data = await Portal.fetchJSON(`/api/managed-services/${serviceId}/logs?limit=200`);
        const logs = data.logs || [];
        if (!logs.length) { box.innerHTML = '<span style="color:var(--text-muted);">No logs.</span>'; return; }
        const colors = { error: 'var(--accent-red)', warn: 'var(--accent-yellow)', info: 'var(--accent-blue)' };
        box.innerHTML = logs.map(l => {
            const t = l.created_at ? new Date(l.created_at + 'Z').toLocaleTimeString() : '';
            return `<div><span style="color:var(--text-muted);">${t}</span> <span style="color:${colors[l.level] || 'var(--text-secondary)'};">[${(l.level || '').toUpperCase()}]</span> ${escapeHtml(l.message)}</div>`;
        }).join('');
    } catch (e) {
        box.innerHTML = `<span style="color:var(--accent-red);">Failed to load logs: ${escapeHtml(e.message || '')}</span>`;
    }
}

// ---- Game server file browser (shared modal #gs-config-modal) ----
let _gsCfg = { gsId: null, root: 'install', dir: '', path: null, readRoot: 'install', writable: false, entries: [], pinned: [] };
let _gsNavSeq = 0;   // guards against a slow response landing after a newer navigation
let _gsSort = { key: 'name', dir: 1 };

// Mirrors gameservers._BROWSE_UPLOAD_SUFFIXES — a client-side hint only (so
// Rename/Delete don't appear on files the server would refuse anyway); the
// server re-checks independently and is authoritative.
const _GS_MODIFY_SUFFIXES = ['.ini', '.cfg', '.conf', '.config', '.json', '.xml', '.yaml', '.yml',
    '.toml', '.txt', '.properties', '.props', '.cnf', '.settings', '.list', '.ecf'];
function _gsCanModify(name) {
    const i = name.lastIndexOf('.');
    return i > -1 && _GS_MODIFY_SUFFIXES.includes(name.slice(i).toLowerCase());
}

async function showGameServerFiles(serviceId, name) {
    document.getElementById('gs-config-title').textContent = name;
    gsFilesCloseEditor();
    document.getElementById('gs-config-roots').innerHTML = '';
    document.getElementById('gs-config-crumbs').textContent = '';
    const bbtn = document.getElementById('gs-config-backup');
    if (bbtn) { bbtn.disabled = true; bbtn.textContent = 'Download backup'; delete bbtn.dataset.loaded; }
    const listEl = document.getElementById('gs-config-files');
    listEl.innerHTML = '<div class="loading"><div class="spinner"></div> Loading…</div>';
    if (typeof showModal === 'function') showModal('gs-config-modal');
    else document.getElementById('gs-config-modal').style.display = 'flex';
    _gsInitDropzone();
    try {
        const servers = (await Portal.fetchJSON('/api/game-servers')).game_servers || [];
        const gs = servers.find(s => s.service_id === serviceId);
        if (!gs) { listEl.innerHTML = '<span style="color:var(--accent-red);">Server not found.</span>'; return; }
        _gsCfg = { gsId: gs.id, root: 'install', dir: '', path: null, readRoot: 'install', writable: false, entries: [], pinned: [] };
        gsFilesNav('install', '');
    } catch (e) {
        listEl.innerHTML = `<span style="color:var(--accent-red);">Failed: ${escapeHtml(e.message || '')}</span>`;
    }
}

function _gsInitDropzone() {
    const box = document.getElementById('gs-config-files');
    if (!box || box.dataset.dropInit) return;
    box.dataset.dropInit = '1';
    box.addEventListener('dragover', e => { e.preventDefault(); box.classList.add('gsf-dragover'); });
    box.addEventListener('dragleave', e => { if (e.target === box) box.classList.remove('gsf-dragover'); });
    box.addEventListener('drop', e => {
        e.preventDefault();
        box.classList.remove('gsf-dragover');
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) gsFilesUpload(e.dataTransfer.files);
    });
    // Right-click on empty list space (not a row, which stops propagation) — upload here.
    box.addEventListener('contextmenu', e => {
        if (e.target !== box) return;
        e.preventDefault();
        FileBrowser.showContextMenu(e.clientX, e.clientY, [
            { label: 'Upload files here', onClick: () => document.getElementById('gs-config-upload-input').click() },
        ]);
    });
}

async function gsFilesNav(root, dir) {
    const seq = ++_gsNavSeq;
    const box = document.getElementById('gs-config-files');
    box.innerHTML = '<div class="loading"><div class="spinner"></div> Loading…</div>';
    try {
        const d = await Portal.fetchJSON(
            `/api/game-servers/${_gsCfg.gsId}/files?root=${encodeURIComponent(root)}&path=${encodeURIComponent(dir || '')}`);
        if (seq !== _gsNavSeq) return;   // a newer navigation started — drop this stale response
        _gsCfg.root = d.root; _gsCfg.dir = d.path || '';
        _gsCfg.entries = d.entries || []; _gsCfg.pinned = d.pinned || [];
        document.getElementById('gs-config-roots').innerHTML = (d.roots || []).map(r =>
            `<button class="btn btn-sm ${r.key === d.root ? 'btn-primary' : 'btn-secondary'}" onclick="gsFilesNav('${r.key}','')">${escapeHtml(r.label)}</button>`
        ).join('');
        const parts = (d.path || '').split('/').filter(Boolean);
        let acc = '';
        const crumbs = [`<a href="#" onclick="event.preventDefault();gsFilesNav('${d.root}','')">/</a>`];
        parts.forEach(p => {
            acc = acc ? acc + '/' + p : p;
            const a = acc.replace(/'/g, "\\'");
            crumbs.push(`<a href="#" onclick="event.preventDefault();gsFilesNav('${d.root}','${a}')">${escapeHtml(p)}</a>`);
        });
        document.getElementById('gs-config-crumbs').innerHTML = crumbs.join(' / ');
        _gsRenderList();
    } catch (e) {
        if (seq !== _gsNavSeq) return;
        box.innerHTML = `<span style="color:var(--accent-red);">${escapeHtml(e.message || 'Failed to load')}</span>`;
    }
    if (seq !== _gsNavSeq) return;
    const bbtn = document.getElementById('gs-config-backup');
    if (bbtn && !bbtn.dataset.loaded) {
        try {
            const c = await Portal.fetchJSON(`/api/game-servers/${_gsCfg.gsId}/config`);
            if (seq !== _gsNavSeq) return;
            bbtn.dataset.loaded = '1';
            const bc = (c.backup_files || []).length;
            bbtn.disabled = bc === 0;
            bbtn.textContent = bc
                ? `Download backup (${bc} file${bc === 1 ? '' : 's'}, ${FileBrowser.fmtBytes(c.backup_total)})`
                : 'Nothing to back up yet';
        } catch (e) { /* keep default */ }
    }
}

// Re-renders #gs-config-files from the already-fetched _gsCfg.entries/pinned —
// used both after a fetch and after the user clicks a sortable column header
// (no refetch needed for a re-sort).
function _gsRenderList() {
    const box = document.getElementById('gs-config-files');
    const root = _gsCfg.root, dir = _gsCfg.dir;
    const pinned = _gsCfg.pinned || [];
    let html = '<div class="gsf-list-head">'
        + '<span style="flex:1;" data-sort-key="name">Name</span>'
        + '<span class="gsf-col-size" data-sort-key="size">Size</span>'
        + '<span class="gsf-col-mtime" data-sort-key="mtime">Modified</span></div>';
    if (pinned.length && !dir) {
        html += '<div class="gsf-pin-label">Settings files</div>';
        html += pinned.map(f => _gsFileRow(f.name, f.path, f.size, f.mtime, f.root || root, true)).join('');
        html += '<div class="gsf-pin-divider"></div>';
    }
    if (dir) {
        const up = dir.split('/').slice(0, -1).join('/');
        html += `<div class="gsf-entry gsf-entry-up" data-up="${FileBrowser.escapeAttr(up)}"><span class="gsf-entry-name">${FileBrowser.ICON_DIR} ..</span></div>`;
    }
    const sorted = FileBrowser.sortEntries(_gsCfg.entries, _gsSort.key, _gsSort.dir);
    if (!sorted.length && !pinned.length) {
        html += '<span style="color:var(--text-muted); padding:0.6rem 0.75rem; display:block;">Empty — start the server once so it generates its files.</span>';
    }
    html += sorted.map(e => e.type === 'directory'
        ? `<div class="gsf-entry" data-type="directory" data-root="${FileBrowser.escapeAttr(root)}" data-path="${FileBrowser.escapeAttr(e.path)}" data-name="${FileBrowser.escapeAttr(e.name)}"><span class="gsf-entry-name">${FileBrowser.ICON_DIR} ${escapeHtml(e.name)}</span><span class="gsf-col-size"></span><span class="gsf-col-mtime">${FileBrowser.fmtMtime(e.mtime)}</span></div>`
        : _gsFileRow(e.name, e.path, e.size, e.mtime, root, e.writable)
    ).join('');
    box.innerHTML = html;
    FileBrowser.initSortableHeader(box.querySelector('.gsf-list-head'), _gsSort, _gsRenderList);
}

// Rows carry path/name/root/writable as data-* attributes (FileBrowser.escapeAttr
// handles '"' too, unlike a plain '.replace(/'/g, ...)') read back via .dataset
// by the delegated listener below, instead of being baked into inline
// onclick/oncontextmenu JS — a filename with a quote can't break the attribute.
function _gsFileRow(name, path, size, mtime, root, writable) {
    return `<div class="gsf-entry" data-type="file" data-root="${FileBrowser.escapeAttr(root)}" data-path="${FileBrowser.escapeAttr(path)}" data-name="${FileBrowser.escapeAttr(name)}" data-writable="${writable ? '1' : '0'}"><span class="gsf-entry-name">${FileBrowser.ICON_FILE} ${escapeHtml(name)}</span><span class="gsf-col-size">${FileBrowser.fmtBytes(size)}</span><span class="gsf-col-mtime">${FileBrowser.fmtMtime(mtime)}</span></div>`;
}

// Installed once — reads root/path/name/type/writable off the entry's
// dataset rather than an inline onclick/oncontextmenu.
(function gsInitRowDelegation() {
    const box = document.getElementById('gs-config-files');
    if (!box) return;
    box.addEventListener('click', (evt) => {
        const upEl = evt.target.closest('.gsf-entry-up');
        if (upEl) { gsFilesNav(_gsCfg.root, upEl.dataset.up); return; }
        const el = evt.target.closest('.gsf-entry[data-type]');
        if (!el) return;
        const { root, path, type } = el.dataset;
        if (type === 'directory') gsFilesNav(root, path);
        else gsFilesOpen(root, path, el.dataset.writable === '1');
    });
    box.addEventListener('contextmenu', (evt) => {
        if (evt.target.closest('.gsf-entry-up')) { evt.preventDefault(); return; }
        const el = evt.target.closest('.gsf-entry[data-type]');
        if (!el) return;
        const { root, path, name, type } = el.dataset;
        gsShowRowMenu(evt, type, root, path, name, el.dataset.writable === '1');
    });
})();

function gsShowRowMenu(evt, type, root, path, name, writable) {
    evt.preventDefault(); evt.stopPropagation();
    const items = [];
    if (type === 'directory') {
        items.push({ label: 'Open', onClick: () => gsFilesNav(root, path) });
    } else {
        items.push({ label: writable ? 'Edit' : 'View', onClick: () => gsFilesOpen(root, path, writable) });
        items.push({ label: 'Download', onClick: () => gsDownloadFileAt(root, path, name) });
        if (_gsCanModify(name)) {
            items.push({ separator: true });
            items.push({ label: 'Rename…', onClick: () => gsFilesRenamePrompt(root, path, name) });
            items.push({ label: 'Delete…', danger: true, onClick: () => gsFilesDeleteConfirm(root, path, name) });
        }
    }
    FileBrowser.showContextMenu(evt.clientX, evt.clientY, items);
}

async function gsFilesRenamePrompt(root, path, oldName) {
    const newName = prompt('Rename to:', oldName);
    if (!newName || newName === oldName) return;
    try {
        const res = await Portal.fetch(`/api/game-servers/${_gsCfg.gsId}/files/rename`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ root, path, new_name: newName }),
        });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error || 'Rename failed');
        Portal.toast('Renamed');
        if (_gsCfg.path === path) gsFilesCloseEditor();
        gsFilesNav(_gsCfg.root, _gsCfg.dir);
    } catch (e) { Portal.toast(e.message || 'Rename failed', 'error'); }
}

async function gsFilesDeleteConfirm(root, path, name) {
    if (!confirm(`Delete "${name}"? This can't be undone.`)) return;
    try {
        const res = await Portal.fetch(
            `/api/game-servers/${_gsCfg.gsId}/files/delete?root=${encodeURIComponent(root)}&path=${encodeURIComponent(path)}`,
            { method: 'DELETE' });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error || 'Delete failed');
        Portal.toast('Deleted');
        if (_gsCfg.path === path) gsFilesCloseEditor();
        gsFilesNav(_gsCfg.root, _gsCfg.dir);
    } catch (e) { Portal.toast(e.message || 'Delete failed', 'error'); }
}

// Attached once — reused for the modal's whole lifetime via
// FileEditor.setValue/getValue/setMode/setReadOnly rather than re-attaching
// per file. See fileeditor.js.
const _gsCM = document.getElementById('gs-config-text')
    ? FileEditor.attach(document.getElementById('gs-config-text'), { readOnly: true })
    : null;

async function gsFilesOpen(root, path, writable) {
    try {
        const d = await Portal.fetchJSON(
            `/api/game-servers/${_gsCfg.gsId}/files/read?root=${encodeURIComponent(root)}&path=${encodeURIComponent(path)}`);
        _gsCfg.path = path; _gsCfg.readRoot = root; _gsCfg.writable = !!d.writable;
        document.getElementById('gs-config-current').textContent = path;
        document.getElementById('gs-config-dl1').style.display = '';
        const canModify = _gsCanModify(path.split('/').pop() || '');
        document.getElementById('gs-config-rename1').style.display = canModify ? '' : 'none';
        document.getElementById('gs-config-del1').style.display = canModify ? '' : 'none';
        FileEditor.setMode(_gsCM, path);
        FileEditor.setValue(_gsCM, d.content);
        FileEditor.setReadOnly(_gsCM, !d.writable);
        document.getElementById('gs-config-save').disabled = !d.writable;
        document.getElementById('gs-config-hint').textContent = d.writable
            ? '' : 'Read-only file type — download to edit elsewhere.';
        document.getElementById('gs-config-listview').style.display = 'none';
        document.getElementById('gs-config-editview').style.display = 'flex';
        FileEditor.refresh(_gsCM);
    } catch (e) {
        Portal.toast(e.message || 'Failed to read file', 'error');
    }
}

function gsFilesCloseEditor() {
    document.getElementById('gs-config-editview').style.display = 'none';
    document.getElementById('gs-config-listview').style.display = 'flex';
    document.getElementById('gs-config-current').textContent = '';
    document.getElementById('gs-config-hint').textContent = '';
    document.getElementById('gs-config-dl1').style.display = 'none';
    document.getElementById('gs-config-rename1').style.display = 'none';
    document.getElementById('gs-config-del1').style.display = 'none';
    FileEditor.setValue(_gsCM, '');
    FileEditor.setReadOnly(_gsCM, true);
    document.getElementById('gs-config-save').disabled = true;
    if (_gsCfg) { _gsCfg.path = null; _gsCfg.writable = false; }
}

function gsFilesRenameCurrent() {
    if (!_gsCfg.path) return;
    gsFilesRenamePrompt(_gsCfg.readRoot, _gsCfg.path, _gsCfg.path.split('/').pop());
}

function gsFilesDeleteCurrent() {
    if (!_gsCfg.path) return;
    gsFilesDeleteConfirm(_gsCfg.readRoot, _gsCfg.path, _gsCfg.path.split('/').pop());
}

async function gsFilesUpload(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length || !_gsCfg || !_gsCfg.gsId) return;
    const root = _gsCfg.root || 'install';
    const dir = _gsCfg.dir || '';
    const fd = new FormData();
    fd.append('root', root);
    fd.append('path', dir);
    files.forEach(f => fd.append('file', f, f.name));
    try {
        const res = await Portal.fetch(`/api/game-servers/${_gsCfg.gsId}/files/upload`, { method: 'POST', body: fd });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Upload failed');
        const results = data.results || [];
        const ok = results.filter(r => r.ok);
        const failed = results.filter(r => !r.ok);
        if (ok.length) {
            Portal.toast(`Uploaded ${ok.length} file${ok.length === 1 ? '' : 's'}${failed.length ? ` — ${failed.length} failed` : ''}`,
                failed.length ? 'error' : 'success');
        }
        failed.forEach(r => Portal.toast(`${r.name || 'file'}: ${r.error || 'failed'}`, 'error'));
        gsFilesNav(root, dir);
    } catch (e) { Portal.toast(e.message || 'Upload failed', 'error'); }
}

async function gsDownloadFileAt(root, path, name) {
    try {
        const res = await Portal.fetch(
            `/api/game-servers/${_gsCfg.gsId}/files/download?root=${encodeURIComponent(root)}&path=${encodeURIComponent(path)}`);
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Download failed');
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name || path.split('/').pop() || 'file';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
    } catch (e) {
        Portal.toast(e.message || 'Download failed', 'error');
    }
}

function gsFilesDownloadFile() {
    if (!_gsCfg.path) return;
    gsDownloadFileAt(_gsCfg.readRoot, _gsCfg.path, _gsCfg.path.split('/').pop());
}

async function downloadGsBackup() {
    if (!_gsCfg.gsId) return;
    const btn = document.getElementById('gs-config-backup');
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = 'Packaging…';
    try {
        const res = await Portal.fetch(`/api/game-servers/${_gsCfg.gsId}/config/download`);
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Backup failed');
        const blob = await res.blob();
        const m = (res.headers.get('Content-Disposition') || '').match(/filename="(.+?)"/);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = m ? m[1] : 'backup.tar.gz';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
    } catch (e) {
        Portal.toast(e.message || 'Backup failed', 'error');
    } finally {
        btn.disabled = false; btn.textContent = label;
    }
}

async function saveGsConfig() {
    if (!_gsCfg.path || !_gsCfg.writable) return;
    try {
        const res = await Portal.fetch(`/api/game-servers/${_gsCfg.gsId}/files/write`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ root: _gsCfg.readRoot, path: _gsCfg.path, content: FileEditor.getValue(_gsCM) }),
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Save failed');
        Portal.toast('Saved');
    } catch (e) {
        Portal.toast(e.message || 'Save failed', 'error');
    }
}

/**
 * Filter services by category
 */
function filterByCategory(categoryId) {
    currentCategory = categoryId;

    // Update active state in sidebar
    document.querySelectorAll('.sidebar a[data-category]').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.category == categoryId) {
            link.classList.add('active');
        }
    });

    // Update title
    const title = document.getElementById('content-title');
    if (categoryId === 'all') {
        title.textContent = 'All Services';
    } else {
        title.textContent = 'Category Services';
    }

    renderServices();
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Handle category clicks
document.addEventListener('click', (e) => {
    const categoryLink = e.target.closest('a[data-category]');
    if (categoryLink) {
        e.preventDefault();
        filterByCategory(categoryLink.dataset.category);
    }
});

/**
 * Load dashboard stats
 */
async function loadDashboardStats() {
    try {
        // Load public stats (live streams, online users, total services)
        const publicStats = await Portal.api('/api/stats/public');
        const statLiveStreams = document.getElementById('stat-live-streams');
        const statOnlineUsers = document.getElementById('stat-online-users');
        if (statLiveStreams && publicStats.live_streams !== undefined) {
            statLiveStreams.textContent = publicStats.live_streams;
        }
        if (statOnlineUsers && publicStats.online_users !== undefined) {
            statOnlineUsers.textContent = publicStats.online_users;
        }

        // Populate community stats (visible to all users)
        const statTotalUsers = document.getElementById('stat-total-users');
        const statActiveSessions = document.getElementById('stat-active-sessions');
        const statTotalServices = document.getElementById('stat-total-services');
        const statUptime = document.getElementById('stat-uptime');
        if (statTotalUsers && publicStats.total_users !== undefined) statTotalUsers.textContent = publicStats.total_users;
        if (statActiveSessions && publicStats.active_sessions !== undefined) statActiveSessions.textContent = publicStats.active_sessions;
        if (statTotalServices && publicStats.total_services !== undefined) statTotalServices.textContent = publicStats.total_services;
        if (statUptime && publicStats.uptime) statUptime.textContent = publicStats.uptime;

        // Load connections count
        const connections = await Portal.api('/api/connections');
        const statConnections = document.getElementById('stat-connections');
        if (statConnections && connections.connections) {
            statConnections.textContent = connections.connections.length;
        }

        // Load SSH keys count
        const keys = await Portal.api('/api/ssh-keys');
        const statKeys = document.getElementById('stat-keys');
        if (statKeys && keys.keys) {
            statKeys.textContent = keys.keys.length;
        }

        // Show admin-only elements if user is admin
        if (Portal.isAdmin(currentUser)) {
            const adminServiceActions = document.getElementById('admin-service-actions');
            const adminPanelCard = document.getElementById('admin-panel-card');
            if (adminServiceActions) adminServiceActions.style.display = 'flex';
            if (adminPanelCard) adminPanelCard.style.display = 'block';
        }
    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

/**
 * Periodically refresh public stats (every 10 seconds)
 */
setInterval(async () => {
    if (document.hidden) return;
    try {
        const publicStats = await Portal.api('/api/stats/public');
        const statLiveStreams = document.getElementById('stat-live-streams');
        const statOnlineUsers = document.getElementById('stat-online-users');
        if (statLiveStreams && publicStats.live_streams !== undefined) {
            statLiveStreams.textContent = publicStats.live_streams;
        }
        if (statOnlineUsers && publicStats.online_users !== undefined) {
            statOnlineUsers.textContent = publicStats.online_users;
        }
        // Update community stats
        const statTotalUsers = document.getElementById('stat-total-users');
        const statActiveSessions = document.getElementById('stat-active-sessions');
        const statTotalServices = document.getElementById('stat-total-services');
        const statUptime = document.getElementById('stat-uptime');
        if (statTotalUsers && publicStats.total_users !== undefined) statTotalUsers.textContent = publicStats.total_users;
        if (statActiveSessions && publicStats.active_sessions !== undefined) statActiveSessions.textContent = publicStats.active_sessions;
        if (statTotalServices && publicStats.total_services !== undefined) statTotalServices.textContent = publicStats.total_services;
        if (statUptime && publicStats.uptime) statUptime.textContent = publicStats.uptime;
        // Refresh activity feed
        await loadActivityFeed();
    } catch (error) {
        // Silent failure for periodic updates
    }
}, 10000);

/**
 * Switch between tabs
 */
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    const activeTab = document.getElementById('tab-' + tabName);
    if (activeTab) {
        activeTab.classList.add('active');
    }

    // Load content for the tab if needed
    if (tabName === 'my-connections') {
        loadInlineConnections();
    } else if (tabName === 'my-streams') {
        // streams.js handles this via its switchTab wrapper (loadUserStreams)
    } else if (tabName === 'my-vods') {
        loadVods();
    }

}

/**
 * Toggle pin status for a connection
 */
async function togglePin(connId) {
    try {
        const data = await Portal.api(`/api/connections/${connId}/pin`, { method: 'POST' });
        Portal.toast(data.is_pinned ? 'Connection pinned' : 'Connection unpinned', 'success');
        loadInlineConnections();
    } catch (error) {
        Portal.toast(error.message || 'Failed to toggle pin', 'error');
    }
}

/**
 * Load connections inline (in the My Connections tab)
 */
async function loadInlineConnections() {
    const loading = document.getElementById('inline-connections-loading');
    const grid = document.getElementById('inline-connections-grid');
    const empty = document.getElementById('inline-connections-empty');

    if (!grid) return;

    loading.style.display = 'flex';
    grid.style.display = 'none';
    empty.style.display = 'none';

    try {
        const data = await Portal.api('/api/connections');
        const connections = data.connections || [];

        if (connections.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            return;
        }

        grid.innerHTML = connections.map(conn => {
            const connType = conn.type || 'unknown';
            const typeBadge = `<span class="conn-type-badge conn-type-${escapeHtml(connType)}">${escapeHtml(connType.toUpperCase())}</span>`;
            const usageText = conn.last_used_at ? Portal.formatRelativeTime(conn.last_used_at) : '';
            const useCount = conn.use_count || 0;
            const isPinned = conn.is_pinned;
            const sshIndicator = conn.ssh_key_name
                ? `<span class="conn-ssh-key" title="SSH Key: ${escapeHtml(conn.ssh_key_name)}"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="12" height="12"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg></span>`
                : '';
            const pinnedClass = isPinned ? ' connection-card-pinned' : '';
            const safeName = escapeHtml(conn.name).replace(/'/g, "\\'");
            const shareIcon = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" /></svg>';
            const actions = conn.shared ? `
                    <button class="btn btn-primary btn-sm connection-connect-btn" onclick="connectTo('${conn.id}')">Connect</button>
                    <button class="btn btn-secondary btn-sm" onclick="leaveSharedConnection('${conn.id}')" title="Remove my access">Leave</button>
                ` : `
                    <button class="btn btn-primary btn-sm connection-connect-btn" onclick="connectTo('${conn.id}')">Connect</button>
                    <button class="btn btn-sm ${isPinned ? 'btn-primary' : 'btn-secondary'}" onclick="togglePin('${conn.id}')" title="${isPinned ? 'Unpin' : 'Pin'}">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="${isPinned ? 'currentColor' : 'none'}" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z" />
                        </svg>
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="showShareConnectionModal('${conn.id}', '${safeName}')" title="Share">${shareIcon}</button>
                    <button class="btn btn-secondary btn-sm" onclick="editConnection('${conn.id}')" title="Edit">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="confirmDeleteConnection('${conn.id}', '${safeName}')" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                    </button>
                `;
            return `<div class="connection-card${pinnedClass}">
                <div class="connection-card-header">
                    <div class="connection-icon">
                        ${getConnectionIcon(conn.icon || conn.type)}
                    </div>
                    <div class="connection-info">
                        <h4>${escapeHtml(conn.name)} ${typeBadge}</h4>
                        <span class="connection-host">${escapeHtml(conn.host)}${conn.port ? ':' + conn.port : ''} ${sshIndicator}</span>
                    </div>
                </div>
                <div class="connection-details">
                    ${conn.shared ? `<span class="connection-time">Shared by ${escapeHtml(conn.owner_username || '?')}</span>`
                        : (usageText ? `<span class="connection-time" title="${useCount} uses">Used ${usageText}</span>` : '<span class="connection-time">Never used</span>')}
                </div>
                <div class="connection-actions">
                    ${actions}
                </div>
            </div>`;
        }).join('');

        loading.style.display = 'none';
        grid.style.display = 'grid';
    } catch (error) {
        console.error('Failed to load connections:', error);
        loading.style.display = 'none';
        empty.style.display = 'block';
    }
}

/**
 * Get icon SVG for connection type
 */
function getConnectionIcon(iconName) {
    const icons = {
        terminal: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>',
        desktop: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>',
        server: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" /></svg>',
        database: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>',
        globe: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>',
        play: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>',
        lock: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>',
        link: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>',
        home: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" /></svg>',
        ssh: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>',
        vnc: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>',
        rdp: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>'
    };
    return icons[iconName] || icons.link;
}

/**
 * Activity feed
 */
let activityFeedCollapsed = false;

const ACTIVITY_MAX_AGE_MS = 60 * 60 * 1000; // 1 hour to fully fade and disappear

let cachedActivities = [];

async function loadActivityFeed() {
    try {
        const data = await Portal.api('/api/activity?limit=3');
        cachedActivities = (data.activities || []).map(a => ({
            ...a,
            _ts: new Date(a.created_at + 'Z').getTime()
        }));
        renderActivityFeed();
    } catch (error) {
        // Silent failure
    }
}

function renderActivityFeed() {
    const feedEl = document.getElementById('activity-feed');
    const listEl = document.getElementById('activity-list');
    if (!feedEl || !listEl) return;

    const now = Date.now();
    const visible = cachedActivities.filter(a => (now - a._ts) < ACTIVITY_MAX_AGE_MS);

    if (visible.length === 0) {
        feedEl.style.display = 'none';
        return;
    }

    feedEl.style.display = 'block';
    listEl.innerHTML = visible.map(a => {
        const icon = getActivityIcon(a.action);
        const age = now - a._ts;
        const time = formatActivityAge(age);
        const opacity = Math.max(0.15, 1 - (age / ACTIVITY_MAX_AGE_MS));
        return `<div class="activity-item" style="opacity: ${opacity.toFixed(2)}">
            <span class="activity-icon">${icon}</span>
            <span class="activity-text"><strong>${escapeHtml(a.username || 'System')}</strong> ${escapeHtml(a.detail || a.action)}</span>
            <span class="activity-time">${time}</span>
        </div>`;
    }).join('');
}

// Update activity timestamps and opacity every 5 seconds
setInterval(renderActivityFeed, 5000);

function formatActivityAge(ageMs) {
    const seconds = Math.floor(ageMs / 1000);
    if (seconds < 5) return 'just now';
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
        const rem = minutes % 60;
        return rem > 0 ? `${hours}h ${rem}m ago` : `${hours}h ago`;
    }
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

function toggleActivityFeed() {
    const body = document.getElementById('activity-feed-body');
    const chevron = document.getElementById('activity-chevron');
    if (!body) return;
    activityFeedCollapsed = !activityFeedCollapsed;
    body.style.display = activityFeedCollapsed ? 'none' : 'block';
    if (chevron) chevron.style.transform = activityFeedCollapsed ? 'rotate(-90deg)' : '';
}

function getActivityIcon(action) {
    const icons = {
        login: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" /></svg>',
        register: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" /></svg>',
        connection_create: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>',
        service_start: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /></svg>',
        service_stop: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" /></svg>',
        stream_live: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>',
        stream_offline: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>',
    };
    return icons[action] || '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>';
}

