/**
 * Open Relay Portal - Dashboard
 */

let services = [];
let currentCategory = 'all';
var currentUser = null;  // shared with admin.js

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    await loadUserInfo();
    await loadServices();
    await loadDashboardStats();
    await loadActivityFeed();
});

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

        if (currentUser.is_admin || role === 'superadmin' || role === 'admin') {
            const adminBadge = document.getElementById('admin-badge');
            const terminalBtn = document.getElementById('terminal-btn');

            if (adminBadge) {
                adminBadge.style.display = 'inline-block';
                adminBadge.textContent = role === 'superadmin' ? 'Super Admin' : 'Admin';
            }
            if (terminalBtn) terminalBtn.style.display = 'flex';
        }

        // Show admin section for moderator+ roles
        if (canManageUsers) {
            const adminSection = document.getElementById('admin-section');
            if (adminSection) adminSection.style.display = 'block';
        }

        // Hide Services tab for non-admin users and switch to My Connections
        if (!currentUser.is_admin && role !== 'superadmin' && role !== 'admin') {
            const servicesTab = document.getElementById('tab-btn-services');
            if (servicesTab) servicesTab.style.display = 'none';
            // Switch to My Connections as default tab for regular users
            switchTab('my-connections');
        }

        // Set profile modal info
        const profileUsername = document.getElementById('profile-username');
        const profileRole = document.getElementById('profile-role');
        if (profileUsername) profileUsername.textContent = currentUser.username;
        if (profileRole) profileRole.textContent = roleLabels[role] || 'User';

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
        renderServices();
    } catch (error) {
        console.error('Failed to load services:', error);
        Portal.toast('Failed to load services', 'error');
    } finally {
        loading.style.display = 'none';
    }
}

/**
 * Refresh services list
 */
async function refreshServices() {
    await loadServices();
    Portal.toast('Services refreshed');
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

    // Filter to only enabled services
    filteredServices = filteredServices.filter(s => s.enabled !== false);

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
            if (service) {
                Portal.openService(service);
            }
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
    const isAdmin = currentUser && currentUser.is_admin;
    const isManaged = service.service_type === 'managed';

    let adminBtns = '';
    if (isAdmin) {
        // Add start/stop buttons for managed services
        let processControls = '';
        if (isManaged) {
            if (service.status === 'running') {
                processControls = `
                    <button class="service-stop-btn" onclick="event.stopPropagation(); stopService(${service.id})" title="Stop service">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
                        </svg>
                    </button>
                `;
            } else {
                processControls = `
                    <button class="service-start-btn" onclick="event.stopPropagation(); startService(${service.id})" title="Start service">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </button>
                `;
            }
        }
        adminBtns = `
            <div class="service-admin-btns">
                ${processControls}
                <button class="service-edit-btn" onclick="event.stopPropagation(); showEditServiceModal(${service.id})" title="Edit service">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                    </svg>
                </button>
                <button class="service-delete-btn" onclick="event.stopPropagation(); confirmDeleteService(${service.id}, '${escapeHtml(service.name).replace(/'/g, "\\'")}')" title="Delete service">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>
        `;
    }

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

    return `
        <div class="service-card" data-service-id="${service.id}">
            ${adminBtns}
            <div class="service-card-header">
                <div class="service-icon">
                    ${icon}
                </div>
                <div class="service-info">
                    <div class="service-name">${escapeHtml(service.display_name || service.name)} ${typeBadge}</div>
                    <div class="service-plugin">${pluginName}</div>
                </div>
            </div>
            <div class="service-status ${statusClass}">
                <span class="service-status-dot"></span>
                ${statusText}
            </div>
        </div>
    `;
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
        if (currentUser && currentUser.is_admin) {
            const adminServiceActions = document.getElementById('admin-service-actions');
            const adminPanelCard = document.getElementById('admin-panel-card');
            if (adminServiceActions) adminServiceActions.style.display = 'flex';
            if (adminPanelCard) adminPanelCard.style.display = 'block';

            // Populate admin stats row
            const adminStats = document.getElementById('admin-stats');
            if (adminStats) {
                adminStats.style.display = 'grid';
                const statTotalUsers = document.getElementById('stat-total-users');
                const statActiveConns = document.getElementById('stat-active-conns');
                const statTotalServices = document.getElementById('stat-total-services');
                const statUptime = document.getElementById('stat-uptime');
                if (statTotalUsers && publicStats.total_users !== undefined) {
                    statTotalUsers.textContent = publicStats.total_users;
                }
                if (statActiveConns && publicStats.active_connections !== undefined) {
                    statActiveConns.textContent = publicStats.active_connections;
                }
                if (statTotalServices && publicStats.total_services !== undefined) {
                    statTotalServices.textContent = publicStats.total_services;
                }
                if (statUptime && publicStats.uptime) {
                    statUptime.textContent = publicStats.uptime;
                }
            }
        }
    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

/**
 * Periodically refresh public stats (every 30 seconds)
 */
setInterval(async () => {
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
        // Update admin stats if visible
        if (currentUser && currentUser.is_admin) {
            const statTotalUsers = document.getElementById('stat-total-users');
            const statActiveConns = document.getElementById('stat-active-conns');
            const statTotalServices = document.getElementById('stat-total-services');
            const statUptime = document.getElementById('stat-uptime');
            if (statTotalUsers && publicStats.total_users !== undefined) statTotalUsers.textContent = publicStats.total_users;
            if (statActiveConns && publicStats.active_connections !== undefined) statActiveConns.textContent = publicStats.active_connections;
            if (statTotalServices && publicStats.total_services !== undefined) statTotalServices.textContent = publicStats.total_services;
            if (statUptime && publicStats.uptime) statUptime.textContent = publicStats.uptime;
        }
        // Refresh activity feed
        await loadActivityFeed();
    } catch (error) {
        // Silent failure for periodic updates
    }
}, 30000);

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
        loadInlineStreams();
    } else if (tabName === 'my-vods') {
        loadVods();
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
            const typeBadge = `<span class="conn-type-badge conn-type-${escapeHtml(conn.type)}">${escapeHtml(conn.type.toUpperCase())}</span>`;
            const created = conn.created_at ? Portal.formatRelativeTime(conn.created_at) : '';
            const sshIndicator = conn.ssh_key_name
                ? `<span class="conn-ssh-key" title="SSH Key: ${escapeHtml(conn.ssh_key_name)}"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="12" height="12"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg></span>`
                : '';
            return `<div class="connection-card">
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
                    ${created ? `<span class="connection-time">${created}</span>` : ''}
                </div>
                <div class="connection-actions">
                    <button class="btn btn-primary btn-sm connection-connect-btn" onclick="connectToConnection(${conn.id})">
                        Connect
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="editConnection(${conn.id})" title="Edit">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="deleteConnection(${conn.id})" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                    </button>
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

async function loadActivityFeed() {
    try {
        const data = await Portal.api('/api/activity?limit=10');
        const activities = data.activities || [];
        const feedEl = document.getElementById('activity-feed');
        const listEl = document.getElementById('activity-list');
        if (!feedEl || !listEl) return;

        if (activities.length === 0) {
            feedEl.style.display = 'none';
            return;
        }

        feedEl.style.display = 'block';
        listEl.innerHTML = activities.map(a => {
            const icon = getActivityIcon(a.action);
            const time = Portal.formatRelativeTime(a.created_at);
            return `<div class="activity-item">
                <span class="activity-icon">${icon}</span>
                <span class="activity-text"><strong>${escapeHtml(a.username || 'System')}</strong> ${escapeHtml(a.detail || a.action)}</span>
                <span class="activity-time">${time}</span>
            </div>`;
        }).join('');
    } catch (error) {
        // Silent failure
    }
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

/**
 * Load inline streams (My Streams tab)
 */
async function loadInlineStreams() {
    const loading = document.getElementById('streams-loading');
    const grid = document.getElementById('streams-grid');
    const empty = document.getElementById('streams-empty');

    if (!grid) return;

    loading.style.display = 'flex';
    grid.style.display = 'none';
    empty.style.display = 'none';

    try {
        const data = await Portal.api('/api/streams');
        const streams = data.streams || [];

        if (streams.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            return;
        }

        grid.innerHTML = streams.map(stream => {
            const isLive = stream.is_live;
            const statusClass = isLive ? 'online' : 'offline';
            const statusText = isLive ? 'Live' : 'Offline';
            const visibilityBadge = stream.is_public
                ? '<span class="stream-badge stream-badge-public">Public</span>'
                : '<span class="stream-badge stream-badge-private">Private</span>';
            const viewerCount = isLive && stream.viewer_count
                ? `<span class="stream-viewers">${stream.viewer_count} viewer${stream.viewer_count !== 1 ? 's' : ''}</span>`
                : '';
            const created = Portal.formatRelativeTime(stream.created_at);
            const maskedKey = stream.stream_key
                ? stream.stream_key.substring(0, 8) + '...'
                : '***';

            return `<div class="connection-card stream-card">
                <div class="connection-card-header">
                    <div class="connection-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                    </div>
                    <div class="connection-info">
                        <h4>${escapeHtml(stream.name)} ${visibilityBadge}</h4>
                        <div class="stream-meta">
                            <span class="service-status ${statusClass}">
                                <span class="service-status-dot"></span>
                                ${statusText}
                            </span>
                            ${viewerCount}
                        </div>
                    </div>
                </div>
                <div class="connection-details">
                    <span class="stream-key-display" title="Click to copy stream key">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="12" height="12">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                        ${maskedKey}
                    </span>
                    <span class="connection-type">${created}</span>
                </div>
                <div class="connection-actions">
                    <button class="btn btn-secondary btn-sm" onclick="copyStreamKey('${escapeHtml(stream.stream_key || '')}')" title="Copy stream key">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                        Key
                    </button>
                    ${stream.public_key ? `<button class="btn btn-secondary btn-sm" onclick="copyStreamKey('${escapeHtml(stream.public_key)}')" title="Copy public key">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                        </svg>
                        Public
                    </button>` : ''}
                    ${isLive ? `<button class="btn btn-primary btn-sm" onclick="window.open('/watch?key=${escapeHtml(stream.public_key || '')}', '_blank')">
                        Watch
                    </button>` : ''}
                </div>
            </div>`;
        }).join('');

        loading.style.display = 'none';
        grid.style.display = 'grid';
    } catch (error) {
        console.error('Failed to load streams:', error);
        loading.style.display = 'none';
        empty.style.display = 'block';
    }
}

function copyStreamKey(key) {
    if (!key) return;
    navigator.clipboard.writeText(key).then(() => {
        Portal.toast('Key copied to clipboard');
    }).catch(() => {
        Portal.toast('Failed to copy key', 'error');
    });
}
