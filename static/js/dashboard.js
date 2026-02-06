/**
 * Portal Gateway - Dashboard
 */

let services = [];
let currentCategory = 'all';
var currentUser = null;  // shared with admin.js

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    await loadUserInfo();
    await loadServices();
    await loadDashboardStats();
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
        const response = await Portal.fetch(`/api/services/${serviceId}/start`, {
            method: 'POST'
        });
        if (response.success) {
            Portal.toast('Service started successfully');
            await loadServices();
        } else {
            Portal.toast(response.error || 'Failed to start service', 'error');
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
        const response = await Portal.fetch(`/api/services/${serviceId}/stop`, {
            method: 'POST'
        });
        if (response.success) {
            Portal.toast('Service stopped successfully');
            await loadServices();
        } else {
            Portal.toast(response.error || 'Failed to stop service', 'error');
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
        // Load public stats (live streams, online users)
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

        grid.innerHTML = connections.map(conn => `
            <div class="connection-card">
                <div class="connection-card-header">
                    <div class="connection-icon">
                        ${getConnectionIcon(conn.icon || conn.type)}
                    </div>
                    <div class="connection-info">
                        <h4>${escapeHtml(conn.name)}</h4>
                        <span class="connection-type">${escapeHtml(conn.type)}</span>
                    </div>
                </div>
                <div class="connection-details">
                    <span class="connection-host">${escapeHtml(conn.host)}${conn.port ? ':' + conn.port : ''}</span>
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
            </div>
        `).join('');

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
