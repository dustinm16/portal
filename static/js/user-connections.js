/**
 * Open Relay Portal - User Connections and API Keys Management
 */

let apiKeys = [];
let userConnections = [];
let connectionTypes = {};
let connectionTypeSchemas = {};
let userSSHKeys = [];

// Connection presets for quick setup
const CONNECTION_PRESETS = {
    'ssh-server': { name: 'SSH Server', type: 'ssh', port: 22, icon: 'terminal', config: { auth_method: 'password' } },
    'vnc-server': { name: 'VNC Desktop', type: 'vnc', port: 5900, icon: 'desktop', config: {} },
    'rdp-server': { name: 'RDP Desktop', type: 'rdp', port: 3389, icon: 'desktop', config: {} },
    'spice-console': { name: 'SPICE Console', type: 'spice', port: 5930, icon: 'desktop', config: {} },
    'mediamtx-rtsp': { name: 'MediaMTX Stream', type: 'mediamtx', port: 8554, icon: 'play', config: {} },
    'ip-camera': { name: 'IP Camera', type: 'stream', port: 554, icon: 'play', config: { protocol: 'rtsp' } },
    'proxmox-ve': { name: 'Proxmox VE', type: 'proxmox', port: 8006, icon: 'server', config: { verify_ssl: false } },
    'tcp-tunnel': { name: 'TCP Tunnel', type: 'tcp_tunnel', icon: 'link', config: {} },
    'secure-tunnel': { name: 'Secure Tunnel', type: 'secure_tunnel', icon: 'lock', config: {} },
    'vpn-bridge': { name: 'VPN Bridge', type: 'vpn_tunnel', icon: 'lock', config: {} },
    'http-proxy': { name: 'HTTP Proxy', type: 'http_proxy', port: 80, icon: 'globe', config: {} },
    'mysql-db': { name: 'MySQL Database', type: 'database', port: 3306, icon: 'database', config: { db_type: 'mysql' } },
    'postgres-db': { name: 'PostgreSQL Database', type: 'database', port: 5432, icon: 'database', config: { db_type: 'postgresql' } },
    'redis-db': { name: 'Redis', type: 'redis', port: 6379, icon: 'database', config: {} },
};

/**
 * Load connection type schemas from server
 */
async function loadConnectionTypeSchemas() {
    try {
        const response = await Portal.fetch('/api/connections/types');
        if (response.ok) {
            const data = await response.json();
            connectionTypeSchemas = data.types || {};
            console.log('[Connections] Loaded type schemas:', Object.keys(connectionTypeSchemas));
        }
    } catch (error) {
        console.error('[Connections] Error loading type schemas:', error);
    }
}

/**
 * Apply a connection preset
 */
function applyConnectionPreset() {
    const presetSelect = document.getElementById('connection-preset');
    const preset = CONNECTION_PRESETS[presetSelect.value];
    if (!preset) return;

    // Apply preset values
    document.getElementById('connection-name').value = preset.name;
    document.getElementById('connection-type').value = preset.type;
    if (preset.port) document.getElementById('connection-port').value = preset.port;
    if (preset.icon) document.getElementById('connection-icon').value = preset.icon;

    // Trigger type change to show appropriate fields
    onConnectionTypeChange();

    // Apply config values after fields are shown
    setTimeout(() => {
        Object.entries(preset.config || {}).forEach(([key, val]) => {
            // Try dynamic field first
            const dynamicField = document.getElementById(`connection-config-${key}`);
            if (dynamicField) {
                if (dynamicField.type === 'checkbox') {
                    dynamicField.checked = val;
                } else {
                    dynamicField.value = val;
                }
                return;
            }
            // Try static fields
            const staticFields = {
                'auth_method': 'connection-ssh-auth',
                'db_type': 'connection-db-type',
                'verify_ssl': 'connection-proxmox-verify-ssl',
            };
            if (staticFields[key]) {
                const el = document.getElementById(staticFields[key]);
                if (el) {
                    if (el.type === 'checkbox') {
                        el.checked = val;
                    } else {
                        el.value = val;
                    }
                }
            }
        });
    }, 50);

    Portal.toast(`Applied preset: ${preset.name}`);
}

// =============================================================================
// API Keys Management
// =============================================================================

/**
 * Show API Keys modal
 */
async function showApiKeysModal() {
    console.log('[API Keys] Opening modal');
    showModal('api-keys-modal');
    await loadApiKeys();
}

/**
 * Load API keys for current user
 */
async function loadApiKeys() {
    const loading = document.getElementById('api-keys-loading');
    const table = document.getElementById('api-keys-table');
    const empty = document.getElementById('api-keys-empty');

    loading.style.display = 'flex';
    table.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await Portal.fetch('/api/api-keys');

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to load API keys');
        }

        const data = await response.json();
        apiKeys = (data && data.api_keys) ? data.api_keys : [];
        renderApiKeys();
    } catch (error) {
        console.error('[API Keys] Error loading keys:', error);
        Portal.toast(error.message || 'Failed to load API keys', 'error');
    } finally {
        loading.style.display = 'none';
    }
}

/**
 * Render API keys table
 */
function renderApiKeys() {
    const table = document.getElementById('api-keys-table');
    const tbody = document.getElementById('api-keys-tbody');
    const empty = document.getElementById('api-keys-empty');

    if (apiKeys.length === 0) {
        table.style.display = 'none';
        empty.style.display = 'block';
        return;
    }

    table.style.display = 'table';
    empty.style.display = 'none';

    tbody.innerHTML = apiKeys.map(key => {
        const isRevoked = key.revoked;
        const isExpired = key.expires_at && new Date(key.expires_at) < new Date();
        const statusClass = isRevoked ? 'badge-danger' : (isExpired ? 'badge-warning' : 'badge-success');
        const statusText = isRevoked ? 'Revoked' : (isExpired ? 'Expired' : 'Active');

        return `
            <tr class="${isRevoked || isExpired ? 'row-inactive' : ''}">
                <td>${escapeHtml(key.name)}</td>
                <td class="monospace">${key.key_prefix}...</td>
                <td><span class="badge badge-secondary">${key.scopes || '*'}</span></td>
                <td>${formatDate(key.created_at)}</td>
                <td>${key.last_used_at ? formatDate(key.last_used_at) : 'Never'}</td>
                <td>${key.expires_at ? formatDate(key.expires_at) : 'Never'}</td>
                <td>
                    <span class="badge ${statusClass}">${statusText}</span>
                    ${!isRevoked ? `
                        <button class="btn btn-sm btn-warning" onclick="confirmRevokeApiKey(${key.id}, '${escapeHtml(key.name).replace(/'/g, "\\'")}')" title="Revoke key">
                            Revoke
                        </button>
                    ` : ''}
                    <button class="btn btn-sm btn-danger" onclick="confirmDeleteApiKey(${key.id}, '${escapeHtml(key.name).replace(/'/g, "\\'")}')" title="Delete key">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

/**
 * Show create API key form
 */
function showCreateApiKeyForm() {
    document.getElementById('create-api-key-form').style.display = 'block';
    document.getElementById('api-key-name').focus();
}

/**
 * Hide create API key form
 */
function hideCreateApiKeyForm() {
    document.getElementById('create-api-key-form').style.display = 'none';
    document.getElementById('api-key-name').value = '';
    document.getElementById('api-key-scopes').value = '*';
    document.getElementById('api-key-expiry').value = '0';
}

/**
 * Submit create API key form
 */
async function submitCreateApiKey(event) {
    event.preventDefault();

    const name = document.getElementById('api-key-name').value.trim();
    const scopes = document.getElementById('api-key-scopes').value.trim() || '*';
    const expiryDays = parseInt(document.getElementById('api-key-expiry').value) || 0;

    if (!name) {
        Portal.toast('Key name is required', 'error');
        return;
    }

    try {
        const response = await Portal.fetch('/api/api-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                scopes,
                expires_in_days: expiryDays > 0 ? expiryDays : null
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to create API key');
        }

        const keyData = await response.json();
        console.log('[API Keys] Key created:', keyData.key_prefix);

        // Show the key (only time it's available)
        showNewApiKeyDisplay(keyData);

        // Refresh the keys list
        await loadApiKeys();

        // Hide the form
        hideCreateApiKeyForm();

        Portal.toast('API key created successfully');
    } catch (error) {
        console.error('[API Keys] Error creating key:', error);
        Portal.toast(error.message || 'Failed to create API key', 'error');
    }
}

/**
 * Show new API key display
 */
function showNewApiKeyDisplay(keyData) {
    document.getElementById('new-api-key-name').textContent = keyData.name;
    document.getElementById('new-api-key-value').value = keyData.key;
    document.getElementById('new-api-key-display').style.display = 'block';
}

/**
 * Hide new API key display
 */
function hideNewApiKeyDisplay() {
    document.getElementById('new-api-key-display').style.display = 'none';
    document.getElementById('new-api-key-value').value = '';
}

/**
 * Copy API key to clipboard
 */
async function copyApiKey() {
    const input = document.getElementById('new-api-key-value');
    try {
        await navigator.clipboard.writeText(input.value);
        Portal.toast('API key copied to clipboard');
    } catch (error) {
        input.select();
        document.execCommand('copy');
        Portal.toast('API key copied to clipboard');
    }
}

/**
 * Confirm revoke API key
 */
function confirmRevokeApiKey(keyId, keyName) {
    pendingConfirmAction = async () => {
        await revokeApiKey(keyId);
    };

    document.getElementById('confirm-title').textContent = 'Revoke API Key';
    document.getElementById('confirm-message').textContent =
        `Are you sure you want to revoke the API key "${keyName}"? Applications using this key will lose access.`;
    document.getElementById('confirm-btn').textContent = 'Revoke';
    document.getElementById('confirm-btn').className = 'btn btn-warning';

    showModal('confirm-modal');
}

/**
 * Revoke API key
 */
async function revokeApiKey(keyId) {
    try {
        const response = await Portal.fetch(`/api/api-keys/${keyId}/revoke`, {
            method: 'POST'
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to revoke API key');
        }

        console.log('[API Keys] Key revoked:', keyId);
        Portal.toast('API key revoked');
        closeModal('confirm-modal');
        document.getElementById('confirm-btn').className = 'btn btn-danger';
        await loadApiKeys();
    } catch (error) {
        console.error('[API Keys] Error revoking key:', error);
        Portal.toast(error.message || 'Failed to revoke API key', 'error');
    }
}

/**
 * Confirm delete API key
 */
function confirmDeleteApiKey(keyId, keyName) {
    pendingConfirmAction = async () => {
        await deleteApiKey(keyId);
    };

    document.getElementById('confirm-title').textContent = 'Delete API Key';
    document.getElementById('confirm-message').textContent =
        `Are you sure you want to permanently delete the API key "${keyName}"? This action cannot be undone.`;
    document.getElementById('confirm-btn').textContent = 'Delete';
    document.getElementById('confirm-btn').className = 'btn btn-danger';

    showModal('confirm-modal');
}

/**
 * Delete API key
 */
async function deleteApiKey(keyId) {
    try {
        const response = await Portal.fetch(`/api/api-keys/${keyId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to delete API key');
        }

        console.log('[API Keys] Key deleted:', keyId);
        Portal.toast('API key deleted');
        closeModal('confirm-modal');
        await loadApiKeys();
    } catch (error) {
        console.error('[API Keys] Error deleting key:', error);
        Portal.toast(error.message || 'Failed to delete API key', 'error');
    }
}

// =============================================================================
// User Connections Management
// =============================================================================

/**
 * Show Connections modal
 */
async function showConnectionsModal() {
    console.log('[Connections] Opening modal');
    showModal('connections-modal');
    await loadConnections();
}

/**
 * Load user connections
 */
async function loadConnections() {
    const loading = document.getElementById('connections-loading');
    const grid = document.getElementById('connections-grid');
    const empty = document.getElementById('connections-empty');

    loading.style.display = 'flex';
    grid.style.display = 'none';
    empty.style.display = 'none';

    try {
        // Load connection types and connections in parallel
        const [typesResponse, connectionsResponse] = await Promise.all([
            Portal.fetch('/api/connections/types'),
            Portal.fetch('/api/connections')
        ]);

        if (!typesResponse.ok || !connectionsResponse.ok) {
            throw new Error('Failed to load connections');
        }

        const typesData = await typesResponse.json();
        connectionTypes = typesData.types || {};

        const connectionsData = await connectionsResponse.json();
        userConnections = connectionsData.connections || [];

        renderConnections();
    } catch (error) {
        console.error('[Connections] Error loading:', error);
        Portal.toast(error.message || 'Failed to load connections', 'error');
    } finally {
        loading.style.display = 'none';
    }
}

/**
 * Render connections grid
 */
function renderConnections() {
    const grid = document.getElementById('connections-grid');
    const empty = document.getElementById('connections-empty');

    if (userConnections.length === 0) {
        grid.style.display = 'none';
        empty.style.display = 'block';
        return;
    }

    grid.style.display = 'grid';
    empty.style.display = 'none';

    grid.innerHTML = userConnections.map(conn => {
        const typeInfo = connectionTypes[conn.type] || { name: conn.type, icon: 'link' };
        const icon = getConnectionIcon(conn.icon || typeInfo.icon);

        return `
            <div class="connection-card" data-connection-id="${conn.id}">
                <div class="connection-card-actions">
                    <button class="btn-icon" onclick="event.stopPropagation(); editConnection(${conn.id})" title="Edit">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="16" height="16">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                    </button>
                    <button class="btn-icon btn-icon-danger" onclick="event.stopPropagation(); confirmDeleteConnection(${conn.id}, '${escapeHtml(conn.name).replace(/'/g, "\\'")}')" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="16" height="16">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
                <div class="connection-icon">${icon}</div>
                <div class="connection-name">${escapeHtml(conn.name)}</div>
                <div class="connection-type">${typeInfo.name}</div>
                <div class="connection-host">${escapeHtml(conn.host)}${conn.port ? ':' + conn.port : ''}</div>
                <button class="btn btn-primary btn-sm connection-connect-btn" onclick="event.stopPropagation(); connectTo(${conn.id})">
                    Connect
                </button>
            </div>
        `;
    }).join('');
}

/**
 * Get icon SVG for connection type
 */
function getConnectionIcon(iconName) {
    const icons = {
        server: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" /></svg>',
        database: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>',
        desktop: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>',
        terminal: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>',
        globe: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>',
        play: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>',
        lock: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>',
        link: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>'
    };
    return icons[iconName] || icons.link;
}

/**
 * Show add connection modal
 */
async function showAddConnectionModal() {
    // Load schemas if not loaded
    if (Object.keys(connectionTypeSchemas).length === 0) {
        await loadConnectionTypeSchemas();
    }

    // Reset form
    document.getElementById('connection-form').reset();
    document.getElementById('connection-id').value = '';
    document.getElementById('connection-modal-title').textContent = 'Add Connection';
    document.getElementById('connection-submit-btn').textContent = 'Add Connection';

    // Reset preset
    document.getElementById('connection-preset').value = '';

    // Reset SSH private key field placeholder
    const sshKeyField = document.getElementById('connection-ssh-private-key');
    if (sshKeyField) {
        sshKeyField.placeholder = '-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----';
    }

    // Reset database password field placeholder
    const dbPwField = document.getElementById('connection-db-password');
    if (dbPwField) {
        dbPwField.placeholder = '';
    }

    // Reset SSH shell selector
    const sshShellField = document.getElementById('connection-ssh-shell');
    if (sshShellField) sshShellField.value = '';

    // Clear dynamic config fields
    const configFields = document.getElementById('connection-config-fields');
    if (configFields) configFields.innerHTML = '';

    // Reset access control checkboxes to defaults
    document.getElementById('connection-portal-access').checked = true;
    document.getElementById('connection-api-access').checked = false;

    // Show appropriate fields for default type
    onConnectionTypeChange();

    showModal('add-connection-modal');
}

/**
 * Load SSH keys for dropdown
 */
async function loadSSHKeysForDropdown() {
    const select = document.getElementById('connection-ssh-key');
    select.innerHTML = '<option value="">None (password auth)</option>';

    try {
        const response = await Portal.fetch('/api/ssh-keys');
        if (response.ok) {
            const data = await response.json();
            userSSHKeys = data.keys || [];
            userSSHKeys.forEach(key => {
                select.innerHTML += `<option value="${key.id}">${escapeHtml(key.name)} (${key.fingerprint.substring(0, 16)}...)</option>`;
            });
        }
    } catch (error) {
        console.error('[Connections] Error loading SSH keys:', error);
    }
}

/**
 * Handle connection type change - generates dynamic config fields from plugin schema
 */
function onConnectionTypeChange() {
    const type = document.getElementById('connection-type').value;
    const portInput = document.getElementById('connection-port');
    const configFields = document.getElementById('connection-config-fields');

    // Hide all static type-specific fields
    document.querySelectorAll('.connection-type-fields').forEach(el => {
        el.style.display = 'none';
    });

    // Clear dynamic config fields
    if (configFields) configFields.innerHTML = '';

    // Get type info from schema
    const typeInfo = connectionTypeSchemas[type] || {};

    // Set default port if available
    if (typeInfo.default_port && !portInput.value) {
        portInput.value = typeInfo.default_port;
    }

    // For types with static fields, show them
    // Otherwise, generate dynamic fields from schema
    switch (type) {
        case 'ssh':
            document.getElementById('connection-ssh-fields').style.display = 'block';
            if (!portInput.value) portInput.value = '22';
            onSSHAuthChange();
            break;
        case 'rdp':
            document.getElementById('connection-rdp-fields').style.display = 'block';
            if (!portInput.value) portInput.value = '3389';
            break;
        case 'database':
            document.getElementById('connection-db-fields').style.display = 'block';
            if (!portInput.value) portInput.value = '3306';
            break;
        case 'stream':
            document.getElementById('connection-stream-fields').style.display = 'block';
            if (!portInput.value) portInput.value = '554';
            break;
        case 'custom':
            document.getElementById('connection-custom-fields').style.display = 'block';
            break;
        default:
            // Generate dynamic fields from plugin schema
            generateDynamicConfigFields(type, typeInfo);
            break;
    }
}

/**
 * Generate dynamic config fields from plugin schema
 */
function generateDynamicConfigFields(type, typeInfo) {
    const configFields = document.getElementById('connection-config-fields');
    if (!configFields) return;

    const schema = typeInfo.config_schema || {};
    const properties = schema.properties || {};
    const required = schema.required || [];

    // Skip fields that are already in the form (host, port)
    const skipFields = ['host', 'port'];

    Object.entries(properties).forEach(([key, prop]) => {
        if (skipFields.includes(key)) return;

        const field = createConnectionConfigField(key, prop, required.includes(key));
        configFields.appendChild(field);
    });
}

/**
 * Create a form field from schema property
 */
function createConnectionConfigField(key, prop, isRequired) {
    const group = document.createElement('div');
    group.className = 'form-group';

    const label = document.createElement('label');
    label.htmlFor = `connection-config-${key}`;
    label.textContent = prop.title || formatFieldLabel(key);
    if (isRequired) {
        const req = document.createElement('span');
        req.style.color = 'var(--accent-red)';
        req.textContent = ' *';
        label.appendChild(req);
    }

    let input;
    if (prop.enum) {
        // Dropdown for enum values
        input = document.createElement('select');
        prop.enum.forEach(val => {
            const opt = document.createElement('option');
            opt.value = val;
            opt.textContent = val;
            input.appendChild(opt);
        });
    } else if (prop.type === 'boolean') {
        // Checkbox for booleans
        const checkWrapper = document.createElement('div');
        checkWrapper.className = 'checkbox-wrapper';
        input = document.createElement('input');
        input.type = 'checkbox';
        checkWrapper.appendChild(input);
        const checkLabel = document.createElement('span');
        checkLabel.textContent = prop.description || '';
        checkWrapper.appendChild(checkLabel);
        group.appendChild(label);
        input.id = `connection-config-${key}`;
        input.name = key;
        if (prop.default !== undefined) input.checked = prop.default;
        group.appendChild(checkWrapper);
        return group;
    } else if (prop.type === 'integer' || prop.type === 'number') {
        input = document.createElement('input');
        input.type = 'number';
        if (prop.minimum !== undefined) input.min = prop.minimum;
        if (prop.maximum !== undefined) input.max = prop.maximum;
    } else {
        // Text/password input
        input = document.createElement('input');
        input.type = prop.format === 'password' ? 'password' : 'text';
    }

    input.id = `connection-config-${key}`;
    input.name = key;
    if (prop.default !== undefined && prop.type !== 'boolean') {
        input.value = prop.default;
    }
    if (prop.placeholder) input.placeholder = prop.placeholder;
    if (isRequired) input.required = true;

    group.appendChild(label);
    group.appendChild(input);

    // Add description as help text
    if (prop.description) {
        const help = document.createElement('small');
        help.style.color = 'var(--text-muted)';
        help.textContent = prop.description;
        group.appendChild(help);
    }

    return group;
}

/**
 * Format field key as label (snake_case to Title Case)
 */
function formatFieldLabel(key) {
    return key.split('_').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

/**
 * Collect config values from dynamic fields
 */
function collectDynamicConfigFields() {
    const config = {};
    document.querySelectorAll('#connection-config-fields [id^="connection-config-"]').forEach(input => {
        const key = input.name;
        if (!key) return;
        if (input.type === 'checkbox') {
            config[key] = input.checked;
        } else if (input.value !== '') {
            config[key] = input.type === 'number' ? Number(input.value) : input.value;
        }
    });
    return config;
}

/**
 * Handle SSH auth method change
 */
function onSSHAuthChange() {
    const authMethod = document.getElementById('connection-ssh-auth').value;
    const keyFields = document.getElementById('connection-ssh-key-fields');

    if (authMethod === 'key') {
        keyFields.style.display = 'block';
    } else {
        keyFields.style.display = 'none';
    }
}

/**
 * Submit connection form (add or edit)
 */
async function submitConnection(event) {
    event.preventDefault();

    const connectionId = document.getElementById('connection-id').value;
    const isEdit = !!connectionId;

    const type = document.getElementById('connection-type').value;
    const name = document.getElementById('connection-name').value.trim();
    const host = document.getElementById('connection-host').value.trim();
    const port = parseInt(document.getElementById('connection-port').value) || null;
    const icon = document.getElementById('connection-icon').value;

    if (!name) {
        Portal.toast('Connection name is required', 'error');
        document.getElementById('connection-name').focus();
        return;
    }
    if (!host) {
        Portal.toast('Host address is required (e.g., 192.168.1.100)', 'error');
        document.getElementById('connection-host').focus();
        return;
    }

    // Build config based on type
    let config = {};

    // First collect any dynamic config fields
    const dynamicConfig = collectDynamicConfigFields();
    Object.assign(config, dynamicConfig);

    // Then handle static type-specific fields
    switch (type) {
        case 'ssh':
            config.username = document.getElementById('connection-ssh-user').value.trim();
            const sshAuth = document.getElementById('connection-ssh-auth').value;
            config.auth_method = sshAuth;
            if (sshAuth === 'key') {
                const privateKey = document.getElementById('connection-ssh-private-key').value.trim();
                if (privateKey) {
                    config.private_key = privateKey;
                } else if (!isEdit) {
                    // Only require key for new connections, not edits (existing key is preserved on server)
                    Portal.toast('Private key is required for key authentication', 'error');
                    return;
                }
                // For edits: if key is empty, server will preserve existing key
            }
            const sshShell = document.getElementById('connection-ssh-shell').value;
            if (sshShell) config.shell = sshShell;
            break;
        case 'rdp':
            config.username = document.getElementById('connection-rdp-user').value.trim();
            config.domain = document.getElementById('connection-rdp-domain').value.trim();
            break;
        case 'database':
            config.db_type = document.getElementById('connection-db-type').value;
            config.database = document.getElementById('connection-db-name').value.trim();
            config.username = document.getElementById('connection-db-user').value.trim();
            const dbPassword = document.getElementById('connection-db-password').value;
            if (dbPassword) config.password = dbPassword;
            break;
        case 'stream':
            config.protocol = document.getElementById('connection-stream-protocol').value;
            config.path = document.getElementById('connection-stream-path').value.trim();
            break;
        case 'custom':
            config.protocol = document.getElementById('connection-custom-protocol').value.trim();
            break;
        // For other types, config comes from dynamic fields (already collected above)
    }

    // Access control options
    const portalAccess = document.getElementById('connection-portal-access').checked ? 1 : 0;
    const apiAccess = document.getElementById('connection-api-access').checked ? 1 : 0;

    const data = { name, type, host, port, icon, config, portal_access: portalAccess, api_access: apiAccess };

    try {
        const url = isEdit ? `/api/connections/${connectionId}` : '/api/connections';
        const method = isEdit ? 'PUT' : 'POST';

        const response = await Portal.fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to save connection');
        }

        console.log('[Connections] Connection saved');
        Portal.toast(isEdit ? 'Connection updated' : 'Connection added');
        closeModal('add-connection-modal');
        await loadConnections();
    } catch (error) {
        console.error('[Connections] Error saving:', error);
        // Provide more helpful error messages
        let msg = error.message || 'Failed to save connection';
        if (msg.includes('UNIQUE constraint')) {
            msg = 'A connection with this name already exists. Please choose a different name.';
        } else if (msg.includes('Local server')) {
            msg = 'Localhost access is blocked for security. Use a remote host address.';
        } else if (msg.includes('Invalid port')) {
            msg = 'Port must be between 1 and 65535.';
        }
        Portal.toast(msg, 'error');
    }
}

/**
 * Edit connection
 */
async function editConnection(connectionId) {
    // Load schemas if not loaded
    if (Object.keys(connectionTypeSchemas).length === 0) {
        await loadConnectionTypeSchemas();
    }

    try {
        const response = await Portal.fetch(`/api/connections/${connectionId}`);
        if (!response.ok) {
            throw new Error('Failed to load connection');
        }

        const conn = await response.json();

        // Populate form
        document.getElementById('connection-id').value = conn.id;
        document.getElementById('connection-name').value = conn.name;
        document.getElementById('connection-type').value = conn.type;
        document.getElementById('connection-host').value = conn.host;
        document.getElementById('connection-port').value = conn.port || '';
        document.getElementById('connection-icon').value = conn.icon || 'link';

        // Reset preset
        document.getElementById('connection-preset').value = '';

        // Show type-specific fields
        onConnectionTypeChange();

        // Populate type-specific fields
        const config = conn.config || {};
        switch (conn.type) {
            case 'ssh':
                document.getElementById('connection-ssh-user').value = config.username || '';
                document.getElementById('connection-ssh-auth').value = config.auth_method || 'password';
                onSSHAuthChange();
                if (config.private_key) {
                    // Show placeholder to indicate key exists (don't show actual key for security)
                    document.getElementById('connection-ssh-private-key').value = '';
                    document.getElementById('connection-ssh-private-key').placeholder = '(Key stored - leave empty to keep existing, or paste new key to replace)';
                }
                document.getElementById('connection-ssh-shell').value = config.shell || '';
                break;
            case 'rdp':
                document.getElementById('connection-rdp-user').value = config.username || '';
                document.getElementById('connection-rdp-domain').value = config.domain || '';
                break;
            case 'database':
                document.getElementById('connection-db-type').value = config.db_type || 'mysql';
                document.getElementById('connection-db-name').value = config.database || '';
                document.getElementById('connection-db-user').value = config.username || '';
                if (config.password) {
                    const dbPwField = document.getElementById('connection-db-password');
                    if (dbPwField) {
                        dbPwField.value = '';
                        dbPwField.placeholder = '(Password stored - leave empty to keep existing)';
                    }
                }
                break;
            case 'stream':
                document.getElementById('connection-stream-protocol').value = config.protocol || 'rtsp';
                document.getElementById('connection-stream-path').value = config.path || '';
                break;
            case 'custom':
                document.getElementById('connection-custom-protocol').value = config.protocol || '';
                break;
            default:
                // Populate dynamic config fields
                populateDynamicConfigFields(config);
                break;
        }

        // Populate access control checkboxes
        document.getElementById('connection-portal-access').checked = conn.portal_access !== 0;
        document.getElementById('connection-api-access').checked = conn.api_access === 1;

        document.getElementById('connection-modal-title').textContent = 'Edit Connection';
        document.getElementById('connection-submit-btn').textContent = 'Save Changes';

        showModal('add-connection-modal');
    } catch (error) {
        console.error('[Connections] Error loading connection:', error);
        Portal.toast(error.message || 'Failed to load connection', 'error');
    }
}

/**
 * Populate dynamic config fields with existing values
 */
function populateDynamicConfigFields(config) {
    Object.entries(config).forEach(([key, value]) => {
        const input = document.getElementById(`connection-config-${key}`);
        if (input) {
            if (input.type === 'checkbox') {
                input.checked = !!value;
            } else {
                input.value = value;
            }
        }
    });
}

/**
 * Confirm delete connection
 */
function confirmDeleteConnection(connectionId, connectionName) {
    pendingConfirmAction = async () => {
        await deleteConnection(connectionId);
    };

    document.getElementById('confirm-title').textContent = 'Delete Connection';
    document.getElementById('confirm-message').textContent =
        `Are you sure you want to delete the connection "${connectionName}"? This action cannot be undone.`;
    document.getElementById('confirm-btn').textContent = 'Delete';
    document.getElementById('confirm-btn').className = 'btn btn-danger';

    showModal('confirm-modal');
}

/**
 * Delete connection
 */
async function deleteConnection(connectionId) {
    try {
        const response = await Portal.fetch(`/api/connections/${connectionId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to delete connection');
        }

        console.log('[Connections] Connection deleted:', connectionId);
        Portal.toast('Connection deleted');
        closeModal('confirm-modal');
        await loadConnections();
    } catch (error) {
        console.error('[Connections] Error deleting:', error);
        Portal.toast(error.message || 'Failed to delete connection', 'error');
    }
}

/**
 * Connect to a connection
 */
async function connectTo(connectionId) {
    try {
        const response = await Portal.fetch(`/api/connections/${connectionId}/connect`);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to connect');
        }

        const data = await response.json();
        const conn = data.connection;
        const type = conn.type;

        // If server provides a direct URL, use it
        if (data.url) {
            window.open(data.url, '_blank');
            return;
        }

        switch (type) {
            case 'ssh':
            case 'terminal':
                window.open(`/terminal/connect?connection=${connectionId}`, '_blank', 'width=900,height=600');
                break;
            case 'vnc':
            case 'rdp':
                window.open(`/vnc/connect?connection=${connectionId}`, '_blank', 'width=1280,height=800');
                break;
            case 'spice':
                window.open(`/spice/connect?connection=${connectionId}`, '_blank', 'width=1280,height=800');
                break;
            case 'proxmox':
                window.open(`/proxmox/connect?connection=${connectionId}`, '_blank', 'width=1280,height=800');
                break;
            case 'github':
                window.open(`/github/connect?connection=${connectionId}`, '_blank', 'width=1400,height=900');
                break;
            case 'http_proxy':
            case 'http':
            case 'https':
                window.open(`/proxy/${connectionId}`, '_blank');
                break;
            case 'mediamtx':
            case 'stream':
                window.open(`/media/connect?connection=${connectionId}`, '_blank', 'width=1280,height=800');
                break;
            case 'database':
            case 'redis':
            case 'tcp_tunnel':
            case 'secure_tunnel':
            case 'vpn_tunnel':
            case 'custom':
                Portal.toast(`${conn.name}: ${conn.host}:${conn.port}`, 'info');
                break;
            default:
                Portal.toast(`${conn.name || 'Connection'}: ${conn.host}:${conn.port}`, 'info');
        }
    } catch (error) {
        console.error('[Connections] Error connecting:', error);
        Portal.toast(error.message || 'Failed to connect', 'error');
    }
}

/**
 * Format date string (use shared version if available)
 */
if (typeof formatDate !== 'function') {
    function formatDate(dateStr) {
        if (!dateStr) return '';
        const date = new Date(dateStr);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
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
