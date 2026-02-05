/**
 * Portal Gateway - Admin Functions
 */

console.log('admin.js loading...');

// currentUser is defined in dashboard.js
var pendingConfirmAction = null;

/**
 * Initialize admin UI based on user role
 */
async function initAdminUI() {
    try {
        currentUser = await Portal.getCurrentUser();

        if (currentUser.is_admin) {
            // Show admin section
            document.getElementById('admin-section').style.display = 'block';
            document.getElementById('admin-badge').style.display = 'inline';
            document.getElementById('terminal-btn').style.display = 'flex';

            // Update empty state message for admins
            document.getElementById('empty-message').textContent =
                'Click "Add Service" in the sidebar to create your first service.';
        }
    } catch (error) {
        console.error('Failed to init admin UI:', error);
    }
}

/**
 * Show modal by ID
 */
function showModal(modalId) {
    console.log('showModal called:', modalId);
    const modal = document.getElementById(modalId);
    if (!modal) {
        console.error('Modal not found:', modalId);
        alert('Modal not found: ' + modalId);
        return;
    }
    console.log('Modal element found, setting display to flex');
    console.log('Modal before:', modal.style.display);
    modal.style.display = 'flex';
    console.log('Modal after:', modal.style.display);
    console.log('Modal computed style:', window.getComputedStyle(modal).display);
    document.body.style.overflow = 'hidden';
}

/**
 * Close modal by ID
 */
function closeModal(modalId) {
    console.log('closeModal called:', modalId);
    document.getElementById(modalId).style.display = 'none';
    document.body.style.overflow = '';

    // Clean up log auto-refresh if closing logs modal
    if (modalId === 'logs-modal' && typeof logAutoRefreshInterval !== 'undefined' && logAutoRefreshInterval) {
        clearInterval(logAutoRefreshInterval);
        logAutoRefreshInterval = null;
        const checkbox = document.getElementById('log-auto-refresh');
        if (checkbox) checkbox.checked = false;
    }
}

// Plugin configuration cache
var pluginConfigs = {};

/**
 * Show Add Service Modal
 */
async function showAddServiceModal() {
    console.log('showAddServiceModal called');
    document.getElementById('add-service-form').reset();
    document.getElementById('plugin-config-fields').innerHTML = '';
    document.getElementById('common-target-fields').style.display = 'block';
    document.getElementById('service-preset').value = '';

    // Always reload plugins to ensure fresh data
    await loadPluginConfigs();

    showModal('add-service-modal');

    // Small delay to ensure DOM is ready
    setTimeout(() => {
        onPluginChange(); // Initialize plugin-specific fields
    }, 100);
}

/**
 * Load plugin configurations from API
 */
async function loadPluginConfigs() {
    try {
        const response = await Portal.fetch('/api/plugins');
        if (response.ok) {
            const data = await response.json();
            console.log('Loaded plugins:', data.plugins.map(p => p.name));
            data.plugins.forEach(p => {
                pluginConfigs[p.name] = p;
            });
        }
    } catch (error) {
        console.error('Failed to load plugins:', error);
    }
}

/**
 * Service presets with pre-filled values
 */
const SERVICE_PRESETS = {
    'local-shell': {
        name: 'Local Shell',
        path: '/shell',
        plugin: 'terminal',
        host: 'localhost',
        port: 0,
        config: { shell: '/bin/bash' }
    },
    'local-vnc': {
        name: 'Local Desktop',
        path: '/desktop',
        plugin: 'vnc',
        host: 'localhost',
        port: 5900
    },
    'ssh-server': {
        name: 'SSH Server',
        path: '/ssh',
        plugin: 'ssh',
        host: '',
        port: 22
    },
    'vnc-server': {
        name: 'VNC Server',
        path: '/vnc',
        plugin: 'vnc',
        host: '',
        port: 5900
    },
    'rdp-server': {
        name: 'RDP Desktop',
        path: '/rdp',
        plugin: 'vnc',
        host: '',
        port: 3389,
        config: { rfb_version: '3.8' }
    },
    'mediamtx-rtsps': {
        name: 'RTSPS Stream (TLS)',
        path: '/stream',
        plugin: 'mediamtx',
        host: '127.0.0.1',
        port: 8322,  // RTSPS port with TLS
        config: { api_url: 'https://127.0.0.1:9997', protocol: 'rtsps' }
    },
    'mediamtx-hls': {
        name: 'HLS Stream (HTTPS)',
        path: '/live',
        plugin: 'mediamtx',
        host: '127.0.0.1',
        port: 8888,  // HLS with HTTPS
        config: { api_url: 'https://127.0.0.1:9997', protocol: 'hls' }
    },
    'mediamtx-webrtc': {
        name: 'WebRTC Stream',
        path: '/webrtc',
        plugin: 'mediamtx',
        host: '127.0.0.1',
        port: 8889,
        config: { api_url: 'https://127.0.0.1:9997', protocol: 'webrtc' }
    },
    'proxmox-cluster': {
        name: 'Proxmox VE',
        path: '/proxmox',
        plugin: 'proxmox',
        host: '',
        port: 8006,
        config: { verify_ssl: false }
    },
    'spice-vm': {
        name: 'VM Console',
        path: '/vm',
        plugin: 'spice',
        host: '',
        port: 5900
    },
    'https-proxy': {
        name: 'HTTPS Proxy',
        path: '/proxy',
        plugin: 'http_proxy',
        host: '',
        port: 443,
        config: { target_url: 'https://backend.example.com:443' }
    },
    'tcp-tunnel': {
        name: 'TCP Tunnel',
        path: '/tunnel',
        plugin: 'tcp_tunnel',
        host: '',
        port: 0
    },
    'secure-tunnel': {
        name: 'Secure Tunnel',
        path: '/secure',
        plugin: 'secure_tunnel',
        host: '',
        port: 0,
        config: { encryption: 'aes-256-gcm' }
    },
    'vpn-bridge': {
        name: 'VPN Bridge',
        path: '/vpn',
        plugin: 'vpn_tunnel',
        host: 'localhost',
        port: 0,
        config: { mode: 'tun' }
    },
    'github': {
        name: 'GitHub',
        path: '/github',
        plugin: 'github',
        host: 'api.github.com',
        port: 443,
        config: {}
    }
};

/**
 * Apply a service preset
 */
function applyServicePreset() {
    const presetSelect = document.getElementById('service-preset');
    const presetKey = presetSelect.value;

    if (!presetKey) return;

    const preset = SERVICE_PRESETS[presetKey];
    if (!preset) return;

    // Apply preset values
    document.getElementById('service-name').value = preset.name;
    document.getElementById('service-path').value = preset.path;
    document.getElementById('service-plugin').value = preset.plugin;
    document.getElementById('service-host').value = preset.host;
    document.getElementById('service-port').value = preset.port || '';

    // Trigger plugin change to update config fields
    onPluginChange();

    // Apply preset config values if any
    if (preset.config) {
        setTimeout(() => {
            Object.entries(preset.config).forEach(([key, value]) => {
                const input = document.getElementById(`config-${key}`);
                if (input) {
                    if (input.type === 'checkbox') {
                        input.checked = value;
                    } else {
                        input.value = value;
                    }
                }
            });
        }, 50);
    }
}

/**
 * Handle plugin selection change
 */
function onPluginChange() {
    const plugin = document.getElementById('service-plugin').value;
    const configContainer = document.getElementById('plugin-config-fields');
    const commonTarget = document.getElementById('common-target-fields');

    configContainer.innerHTML = '';

    // Show/hide common target fields based on plugin
    const hideCommonFor = ['terminal', 'http_proxy', 'github'];
    commonTarget.style.display = hideCommonFor.includes(plugin) ? 'none' : 'block';

    // Get plugin config schema
    const pluginInfo = pluginConfigs[plugin];
    console.log('Plugin selected:', plugin, 'Config:', pluginInfo);
    if (!pluginInfo || !pluginInfo.config_schema || !pluginInfo.config_schema.properties) {
        console.log('No config schema for plugin:', plugin);
        return;
    }

    const schema = pluginInfo.config_schema;
    const properties = schema.properties;
    const required = schema.required || [];

    // Filter out host/port as they're already in common fields
    const configFields = Object.entries(properties).filter(
        ([key]) => !['host', 'port'].includes(key)
    );

    if (configFields.length === 0) return;

    // Add section header
    const header = document.createElement('div');
    header.className = 'config-section-header';
    header.innerHTML = `<h4 style="margin: 1rem 0 0.5rem; color: var(--text-secondary); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;">${pluginInfo.display_name} Settings</h4>`;
    configContainer.appendChild(header);

    // Add GitHub OAuth helper for GitHub plugin
    if (plugin === 'github') {
        const oauthHelper = document.createElement('div');
        oauthHelper.className = 'oauth-helper';
        oauthHelper.innerHTML = `
            <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
                <p style="color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 0.75rem;">
                    <strong>Authentication Options:</strong>
                </p>
                <div style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.8rem; color: var(--text-muted);">
                    <div><strong style="color: var(--accent-blue);">Option 1 - OAuth App:</strong> Enter Client ID and Client Secret from a <a href="https://github.com/settings/developers" target="_blank" style="color: var(--accent-blue);">GitHub OAuth App</a>. Users will see a "Connect with GitHub" button.</div>
                    <div><strong style="color: var(--accent-green);">Option 2 - Personal Token:</strong> Enter a <a href="https://github.com/settings/tokens" target="_blank" style="color: var(--accent-blue);">Personal Access Token</a> with repo, read:user, and workflow scopes. All users share this token.</div>
                </div>
            </div>
        `;
        configContainer.appendChild(oauthHelper);
    }

    // Generate fields
    configFields.forEach(([key, prop]) => {
        const isRequired = required.includes(key);
        const field = createConfigField(key, prop, isRequired);
        configContainer.appendChild(field);
    });
}

/**
 * Create a form field for a config property
 */
function createConfigField(key, prop, isRequired) {
    const div = document.createElement('div');
    div.className = 'form-group';

    const label = document.createElement('label');
    label.htmlFor = `config-${key}`;
    label.textContent = prop.title || formatLabel(key);
    if (isRequired) {
        label.innerHTML += ' <span style="color: var(--accent-red);">*</span>';
    }
    div.appendChild(label);

    let input;

    if (prop.enum) {
        // Select dropdown for enum types
        input = document.createElement('select');
        input.id = `config-${key}`;
        input.name = `config-${key}`;
        if (isRequired) input.required = true;

        prop.enum.forEach(val => {
            const opt = document.createElement('option');
            opt.value = val;
            opt.textContent = val;
            if (val === prop.default) opt.selected = true;
            input.appendChild(opt);
        });
    } else if (prop.type === 'boolean') {
        // Checkbox for boolean
        const wrapper = document.createElement('label');
        wrapper.className = 'toggle';

        input = document.createElement('input');
        input.type = 'checkbox';
        input.id = `config-${key}`;
        input.name = `config-${key}`;
        if (prop.default) input.checked = true;

        const slider = document.createElement('span');
        slider.className = 'toggle-slider';

        wrapper.appendChild(input);
        wrapper.appendChild(slider);
        div.appendChild(wrapper);

        if (prop.description) {
            const desc = document.createElement('small');
            desc.style.color = 'var(--text-muted)';
            desc.style.display = 'block';
            desc.style.marginTop = '0.25rem';
            desc.textContent = prop.description;
            div.appendChild(desc);
        }
        return div;
    } else if (prop.type === 'integer' || prop.type === 'number') {
        input = document.createElement('input');
        input.type = 'number';
        input.id = `config-${key}`;
        input.name = `config-${key}`;
        if (prop.minimum !== undefined) input.min = prop.minimum;
        if (prop.maximum !== undefined) input.max = prop.maximum;
        if (prop.default !== undefined) input.value = prop.default;
        if (isRequired) input.required = true;
    } else {
        // Text input for strings
        input = document.createElement('input');
        input.type = 'text';
        input.id = `config-${key}`;
        input.name = `config-${key}`;
        if (prop.default !== undefined) input.value = prop.default;
        if (isRequired) input.required = true;
        if (prop.pattern) input.pattern = prop.pattern;
    }

    if (prop.description) {
        input.placeholder = prop.description;
    }

    div.appendChild(input);

    if (prop.description && prop.type !== 'boolean') {
        const desc = document.createElement('small');
        desc.style.color = 'var(--text-muted)';
        desc.textContent = prop.description;
        div.appendChild(desc);
    }

    return div;
}

/**
 * Format a key into a readable label
 */
function formatLabel(key) {
    return key
        .replace(/_/g, ' ')
        .replace(/([A-Z])/g, ' $1')
        .replace(/^./, str => str.toUpperCase())
        .trim();
}

/**
 * Collect plugin configuration from form
 */
function collectPluginConfig() {
    const config = {};
    const configInputs = document.querySelectorAll('[id^="config-"]');

    configInputs.forEach(input => {
        const key = input.id.replace('config-', '');
        if (input.type === 'checkbox') {
            config[key] = input.checked;
        } else if (input.type === 'number' && input.value) {
            config[key] = parseFloat(input.value);
        } else if (input.value) {
            config[key] = input.value;
        }
    });

    return config;
}

/**
 * Submit Add Service Form
 */
async function submitAddService(event) {
    event.preventDefault();

    const name = document.getElementById('service-name').value;
    const path = document.getElementById('service-path').value;
    const plugin = document.getElementById('service-plugin').value;
    const host = document.getElementById('service-host').value;
    const port = document.getElementById('service-port').value;
    const scopes = document.getElementById('service-scopes').value || '*';

    // Collect plugin-specific config
    const config = collectPluginConfig();

    // Ensure path starts with /
    const normalizedPath = path.startsWith('/') ? path : '/' + path;

    try {
        const response = await Portal.fetch('/api/services', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                path: normalizedPath,
                plugin,
                host,
                port: port ? parseInt(port) : 0,
                config,
                required_scopes: scopes
            })
        });

        if (response.ok) {
            Portal.toast('Service added successfully');
            closeModal('add-service-modal');
            await loadServices();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to add service', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to add service', 'error');
        console.error('Add service error:', error);
    }
}

/**
 * Show Edit Service Modal
 */
async function showEditServiceModal(serviceId) {
    console.log('showEditServiceModal called for service:', serviceId);

    // Load plugins if not cached
    if (Object.keys(pluginConfigs).length === 0) {
        await loadPluginConfigs();
    }

    // Fetch service details
    try {
        const response = await Portal.fetch(`/api/services/${serviceId}`);
        if (!response.ok) {
            throw new Error('Failed to load service');
        }
        const service = await response.json();

        // Populate form
        document.getElementById('edit-service-id').value = service.id;
        document.getElementById('edit-service-name').value = service.name;
        document.getElementById('edit-service-path').value = service.path;
        document.getElementById('edit-service-plugin').value = service.plugin || 'tcp_tunnel';
        document.getElementById('edit-service-host').value = service.host || '';
        document.getElementById('edit-service-port').value = service.port || '';
        document.getElementById('edit-service-enabled').checked = service.enabled !== false;

        // Handle scopes - can be string or array
        const scopes = Array.isArray(service.required_scopes)
            ? service.required_scopes.join(', ')
            : service.required_scopes;
        document.getElementById('edit-service-scopes').value = scopes;

        // Update plugin-specific fields
        onEditPluginChange();

        // Apply service config values if any
        if (service.config && typeof service.config === 'object') {
            setTimeout(() => {
                Object.entries(service.config).forEach(([key, value]) => {
                    const input = document.getElementById(`edit-config-${key}`);
                    if (input) {
                        if (input.type === 'checkbox') {
                            input.checked = value;
                        } else {
                            input.value = value;
                        }
                    }
                });
            }, 50);
        }

        showModal('edit-service-modal');
    } catch (error) {
        Portal.toast('Failed to load service details', 'error');
        console.error('Load service error:', error);
    }
}

/**
 * Handle plugin selection change in edit modal
 */
function onEditPluginChange() {
    const plugin = document.getElementById('edit-service-plugin').value;
    const configContainer = document.getElementById('edit-plugin-config-fields');
    const commonTarget = document.getElementById('edit-common-target-fields');

    configContainer.innerHTML = '';

    // Show/hide common target fields based on plugin
    const hideCommonFor = ['terminal', 'http_proxy', 'github'];
    commonTarget.style.display = hideCommonFor.includes(plugin) ? 'none' : 'block';

    // Get plugin config schema
    const pluginInfo = pluginConfigs[plugin];
    if (!pluginInfo || !pluginInfo.config_schema || !pluginInfo.config_schema.properties) {
        return;
    }

    const schema = pluginInfo.config_schema;
    const properties = schema.properties;
    const required = schema.required || [];

    // Filter out host/port as they're already in common fields
    const configFields = Object.entries(properties).filter(
        ([key]) => !['host', 'port'].includes(key)
    );

    if (configFields.length === 0) return;

    // Add section header
    const header = document.createElement('div');
    header.className = 'config-section-header';
    header.innerHTML = `<h4 style="margin: 1rem 0 0.5rem; color: var(--text-secondary); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em;">${pluginInfo.display_name} Settings</h4>`;
    configContainer.appendChild(header);

    // Generate fields
    configFields.forEach(([key, prop]) => {
        const isRequired = required.includes(key);
        const field = createEditConfigField(key, prop, isRequired);
        configContainer.appendChild(field);
    });
}

/**
 * Create a form field for edit config property
 */
function createEditConfigField(key, prop, isRequired) {
    const div = document.createElement('div');
    div.className = 'form-group';

    const label = document.createElement('label');
    label.htmlFor = `edit-config-${key}`;
    label.textContent = prop.title || formatLabel(key);
    if (isRequired) {
        label.innerHTML += ' <span style="color: var(--accent-red);">*</span>';
    }
    div.appendChild(label);

    let input;

    if (prop.enum) {
        input = document.createElement('select');
        input.id = `edit-config-${key}`;
        input.name = `edit-config-${key}`;
        if (isRequired) input.required = true;

        prop.enum.forEach(val => {
            const opt = document.createElement('option');
            opt.value = val;
            opt.textContent = val;
            if (val === prop.default) opt.selected = true;
            input.appendChild(opt);
        });
    } else if (prop.type === 'boolean') {
        const wrapper = document.createElement('label');
        wrapper.className = 'toggle';

        input = document.createElement('input');
        input.type = 'checkbox';
        input.id = `edit-config-${key}`;
        input.name = `edit-config-${key}`;
        if (prop.default) input.checked = true;

        const slider = document.createElement('span');
        slider.className = 'toggle-slider';

        wrapper.appendChild(input);
        wrapper.appendChild(slider);
        div.appendChild(wrapper);

        if (prop.description) {
            const desc = document.createElement('small');
            desc.style.color = 'var(--text-muted)';
            desc.style.display = 'block';
            desc.style.marginTop = '0.25rem';
            desc.textContent = prop.description;
            div.appendChild(desc);
        }
        return div;
    } else if (prop.type === 'integer' || prop.type === 'number') {
        input = document.createElement('input');
        input.type = 'number';
        input.id = `edit-config-${key}`;
        input.name = `edit-config-${key}`;
        if (prop.minimum !== undefined) input.min = prop.minimum;
        if (prop.maximum !== undefined) input.max = prop.maximum;
        if (prop.default !== undefined) input.value = prop.default;
        if (isRequired) input.required = true;
    } else {
        input = document.createElement('input');
        input.type = 'text';
        input.id = `edit-config-${key}`;
        input.name = `edit-config-${key}`;
        if (prop.default !== undefined) input.value = prop.default;
        if (isRequired) input.required = true;
        if (prop.pattern) input.pattern = prop.pattern;
    }

    if (prop.description) {
        input.placeholder = prop.description;
    }

    div.appendChild(input);

    if (prop.description && prop.type !== 'boolean') {
        const desc = document.createElement('small');
        desc.style.color = 'var(--text-muted)';
        desc.textContent = prop.description;
        div.appendChild(desc);
    }

    return div;
}

/**
 * Collect edit plugin configuration from form
 */
function collectEditPluginConfig() {
    const config = {};
    const configInputs = document.querySelectorAll('[id^="edit-config-"]');

    configInputs.forEach(input => {
        const key = input.id.replace('edit-config-', '');
        if (input.type === 'checkbox') {
            config[key] = input.checked;
        } else if (input.type === 'number' && input.value) {
            config[key] = parseFloat(input.value);
        } else if (input.value) {
            config[key] = input.value;
        }
    });

    return config;
}

/**
 * Submit Edit Service Form
 */
async function submitEditService(event) {
    event.preventDefault();

    const serviceId = document.getElementById('edit-service-id').value;
    const name = document.getElementById('edit-service-name').value;
    const path = document.getElementById('edit-service-path').value;
    const plugin = document.getElementById('edit-service-plugin').value;
    const host = document.getElementById('edit-service-host').value;
    const port = document.getElementById('edit-service-port').value;
    const enabled = document.getElementById('edit-service-enabled').checked;
    const scopes = document.getElementById('edit-service-scopes').value || '*';

    // Collect plugin-specific config
    const config = collectEditPluginConfig();

    // Ensure path starts with /
    const normalizedPath = path.startsWith('/') ? path : '/' + path;

    try {
        const response = await Portal.fetch(`/api/services/${serviceId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                path: normalizedPath,
                plugin,
                host,
                port: port ? parseInt(port) : 0,
                enabled,
                config,
                required_scopes: scopes
            })
        });

        if (response.ok) {
            Portal.toast('Service updated successfully');
            closeModal('edit-service-modal');
            await loadServices();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update service', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to update service', 'error');
        console.error('Update service error:', error);
    }
}

// Role management
var manageableRoles = [];
var actorRole = 'user';

const ROLE_LABELS = {
    'superadmin': 'Super Admin',
    'admin': 'Admin',
    'moderator': 'Moderator',
    'user': 'User'
};

const ROLE_COLORS = {
    'superadmin': 'var(--accent-red)',
    'admin': 'var(--accent-purple)',
    'moderator': 'var(--accent-blue)',
    'user': 'var(--text-secondary)'
};

/**
 * Show Manage Users Modal
 */
async function showManageUsersModal() {
    console.log('showManageUsersModal called');
    showModal('manage-users-modal');
    document.getElementById('users-loading').style.display = 'flex';
    document.getElementById('users-table').style.display = 'none';

    try {
        console.log('Fetching users...');
        const response = await Portal.fetch('/api/users');
        console.log('Users response status:', response.status);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to load users');
        }

        const data = await response.json();
        console.log('Users data:', data);

        if (!data || !data.users) {
            throw new Error('Invalid response format');
        }

        // Store actor's role info
        actorRole = data.actor_role || 'user';
        manageableRoles = data.manageable_roles || [];

        renderUsersTable(data.users);
        console.log('Users table rendered');
    } catch (error) {
        Portal.toast(error.message || 'Failed to load users', 'error');
        console.error('Load users error:', error);
        document.getElementById('users-loading').style.display = 'none';
    }
}

/**
 * Check if current user can manage target role
 */
function canManageRole(targetRole) {
    const hierarchy = ['user', 'moderator', 'admin', 'superadmin'];
    const actorLevel = hierarchy.indexOf(actorRole);
    const targetLevel = hierarchy.indexOf(targetRole);
    return actorLevel > targetLevel;
}

/**
 * Render users table
 */
function renderUsersTable(users) {
    console.log('renderUsersTable called with', users?.length, 'users');
    const tbody = document.getElementById('users-tbody');
    console.log('tbody element:', tbody);

    const canResetPasswords = currentUser?.permissions?.can_reset_passwords;
    const canDeleteUsers = currentUser?.permissions?.can_delete_users;

    tbody.innerHTML = users.map(user => {
        const userRole = user.role || 'user';
        const isCurrentUser = user.id === currentUser?.id;
        const canManage = canManageRole(userRole) && !isCurrentUser;

        // Build role select options
        let roleSelect = '';
        if (canManage && manageableRoles.length > 0) {
            const options = manageableRoles.map(r =>
                `<option value="${r}" ${userRole === r ? 'selected' : ''}>${ROLE_LABELS[r]}</option>`
            ).join('');
            roleSelect = `
                <select onchange="changeUserRole(${user.id}, this.value)" style="background: var(--bg-primary); border: 1px solid var(--card-border); color: var(--text-primary); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">
                    ${options}
                </select>
            `;
        } else {
            roleSelect = `<span class="role-badge" style="color: ${ROLE_COLORS[userRole]}; font-weight: 500;">${ROLE_LABELS[userRole]}</span>`;
        }

        // Build action buttons
        let actions = '';
        if (isCurrentUser) {
            actions = '<span style="color: var(--text-muted); font-size: 0.75rem;">Current user</span>';
        } else if (canManage) {
            if (canResetPasswords) {
                actions += `<button class="btn btn-secondary btn-sm" onclick="showResetPasswordModal(${user.id}, '${escapeHtml(user.username).replace(/'/g, "\\'")}')">Reset Password</button> `;
            }
            if (canDeleteUsers) {
                actions += `<button class="btn btn-danger btn-sm" onclick="confirmDeleteUser(${user.id}, '${escapeHtml(user.username).replace(/'/g, "\\'")}')">Delete</button>`;
            }
        } else {
            actions = '<span style="color: var(--text-muted); font-size: 0.65rem;">Cannot manage</span>';
        }

        return `
            <tr data-user-id="${user.id}">
                <td>${user.id}</td>
                <td>${escapeHtml(user.username)}</td>
                <td>${roleSelect}</td>
                <td>${formatDate(user.created_at)}</td>
                <td>${actions}</td>
            </tr>
        `;
    }).join('');

    document.getElementById('users-loading').style.display = 'none';
    document.getElementById('users-table').style.display = 'table';
}

/**
 * Change user role
 */
async function changeUserRole(userId, newRole) {
    try {
        const response = await Portal.fetch(`/api/users/${userId}/role`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: newRole })
        });

        if (response.ok) {
            Portal.toast(`Role updated to ${ROLE_LABELS[newRole]}`);
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update role', 'error');
            // Reload to revert changes
            showManageUsersModal();
        }
    } catch (error) {
        Portal.toast('Failed to update role', 'error');
        console.error('Change role error:', error);
    }
}

/**
 * Legacy toggle function - redirects to role change
 */
async function toggleUserAdmin(userId, isAdmin) {
    await changeUserRole(userId, isAdmin ? 'admin' : 'user');
}

/**
 * Show reset password modal
 */
function showResetPasswordModal(userId, username) {
    document.getElementById('reset-password-user-id').value = userId;
    document.getElementById('reset-password-username').textContent = username;
    document.getElementById('reset-password-input').value = '';
    showModal('reset-password-modal');
}

/**
 * Submit password reset
 */
async function submitResetPassword(event) {
    event.preventDefault();

    const userId = document.getElementById('reset-password-user-id').value;
    const newPassword = document.getElementById('reset-password-input').value;

    if (!newPassword || newPassword.length < 8) {
        Portal.toast('Password must be at least 8 characters', 'error');
        return;
    }

    try {
        const response = await Portal.fetch(`/api/users/${userId}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_password: newPassword })
        });

        if (response.ok) {
            Portal.toast('Password reset successfully');
            closeModal('reset-password-modal');
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to reset password', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to reset password', 'error');
        console.error('Reset password error:', error);
    }
}

/**
 * Show delete user confirmation
 */
function confirmDeleteUser(userId, username) {
    document.getElementById('confirm-title').textContent = 'Delete User';
    document.getElementById('confirm-message').textContent =
        `Are you sure you want to delete user "${username}"? This action cannot be undone.`;
    document.getElementById('confirm-btn').textContent = 'Delete';

    pendingConfirmAction = () => deleteUser(userId);
    showModal('confirm-modal');
}

/**
 * Delete a user
 */
async function deleteUser(userId) {
    try {
        const response = await Portal.fetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            Portal.toast('User deleted');
            closeModal('confirm-modal');
            // Remove row from table
            const row = document.querySelector(`tr[data-user-id="${userId}"]`);
            if (row) row.remove();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to delete user', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to delete user', 'error');
        console.error('Delete user error:', error);
    }
}

/**
 * Show delete service confirmation
 */
function confirmDeleteService(serviceId, serviceName) {
    document.getElementById('confirm-title').textContent = 'Delete Service';
    document.getElementById('confirm-message').textContent =
        `Are you sure you want to delete service "${serviceName}"? This action cannot be undone.`;
    document.getElementById('confirm-btn').textContent = 'Delete';

    pendingConfirmAction = () => deleteService(serviceId);
    showModal('confirm-modal');
}

/**
 * Delete a service
 */
async function deleteService(serviceId) {
    try {
        const response = await Portal.fetch(`/api/services/${serviceId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            Portal.toast('Service deleted');
            closeModal('confirm-modal');
            await loadServices();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to delete service', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to delete service', 'error');
        console.error('Delete service error:', error);
    }
}

/**
 * Execute pending confirm action
 */
function confirmAction() {
    if (pendingConfirmAction) {
        pendingConfirmAction();
        pendingConfirmAction = null;
    }
}

/**
 * Show Invite Code Modal
 */
async function showInviteCode() {
    console.log('showInviteCode called');
    showModal('invite-code-modal');
    const display = document.getElementById('invite-code-display');
    console.log('invite-code-display element:', display);
    display.textContent = 'Loading...';

    try {
        const response = await Portal.fetch('/api/invite-code');

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to load invite code');
        }

        const data = await response.json();

        if (!data || !data.code) {
            throw new Error('Invalid response format');
        }

        document.getElementById('invite-code-display').textContent = data.code;
    } catch (error) {
        document.getElementById('invite-code-display').textContent = 'Error loading code';
        Portal.toast(error.message || 'Failed to load invite code', 'error');
        console.error('Load invite code error:', error);
    }
}

/**
 * Format date for display
 */
function formatDate(dateStr) {
    const date = new Date(dateStr + 'Z'); // Assume UTC
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Log Viewer Functions
// ============================================================================

var logAutoRefreshInterval = null;

/**
 * Show Logs Modal
 */
async function showLogsModal() {
    console.log('showLogsModal called');
    showModal('logs-modal');
    await loadLogFiles();
    await loadLogSettings();
    await loadLogs();
}

/**
 * Load available log files
 */
async function loadLogFiles() {
    try {
        const response = await Portal.fetch('/api/logs/files');
        const data = await response.json();

        const select = document.getElementById('log-file-select');
        select.innerHTML = data.files.map(f =>
            `<option value="${f.name}">${f.name} (${formatFileSize(f.size)})</option>`
        ).join('');
    } catch (error) {
        console.error('Failed to load log files:', error);
    }
}

/**
 * Load log settings
 */
async function loadLogSettings() {
    try {
        const response = await Portal.fetch('/api/logs/settings');
        const data = await response.json();

        document.getElementById('log-level-select').value = data.level;
    } catch (error) {
        console.error('Failed to load log settings:', error);
    }
}

/**
 * Load and display logs
 */
async function loadLogs() {
    const container = document.getElementById('logs-container');
    const filename = document.getElementById('log-file-select').value;

    try {
        const response = await Portal.fetch(`/api/logs?file=${filename}&lines=500`);
        const data = await response.json();

        if (data.error) {
            container.innerHTML = `<div class="logs-content" style="color: var(--accent-red);">Error: ${data.error}</div>`;
            return;
        }

        const lines = data.lines.map(line => {
            const levelClass = getLogLevelClass(line);
            return `<div class="log-line ${levelClass}">${escapeHtml(line)}</div>`;
        }).join('');

        container.innerHTML = `<div class="logs-content">${lines || 'No log entries'}</div>`;

        // Scroll to bottom
        container.scrollTop = container.scrollHeight;
    } catch (error) {
        container.innerHTML = `<div class="logs-content" style="color: var(--accent-red);">Failed to load logs: ${error.message}</div>`;
        console.error('Load logs error:', error);
    }
}

/**
 * Get CSS class for log level
 */
function getLogLevelClass(line) {
    if (line.includes('[DEBUG]')) return 'level-DEBUG';
    if (line.includes('[INFO]')) return 'level-INFO';
    if (line.includes('[WARNING]')) return 'level-WARNING';
    if (line.includes('[ERROR]')) return 'level-ERROR';
    if (line.includes('[CRITICAL]')) return 'level-CRITICAL';
    return '';
}

/**
 * Update log level
 */
async function updateLogLevel() {
    const level = document.getElementById('log-level-select').value;

    try {
        const response = await Portal.fetch('/api/logs/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ level })
        });

        if (response.ok) {
            Portal.toast(`Log level set to ${level}`);
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update log level', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to update log level', 'error');
        console.error('Update log level error:', error);
    }
}

/**
 * Toggle auto-refresh for logs
 */
function toggleAutoRefresh() {
    const checkbox = document.getElementById('log-auto-refresh');

    if (checkbox.checked) {
        logAutoRefreshInterval = setInterval(loadLogs, 3000);
    } else {
        if (logAutoRefreshInterval) {
            clearInterval(logAutoRefreshInterval);
            logAutoRefreshInterval = null;
        }
    }
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ============================================================================
// User Profile Functions
// ============================================================================

/**
 * Show user profile modal
 */
function showProfileModal() {
    if (!currentUser) {
        Portal.toast('User not loaded', 'error');
        return;
    }

    document.getElementById('profile-username').textContent = currentUser.username;
    document.getElementById('profile-role').textContent = currentUser.is_admin ? 'Administrator' : 'User';

    // Clear form
    document.getElementById('change-password-form').reset();

    showModal('profile-modal');

    // Load 2FA status
    load2FAStatus();
}

/**
 * Submit password change form
 */
async function submitChangePassword(event) {
    event.preventDefault();

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (newPassword !== confirmPassword) {
        Portal.toast('New passwords do not match', 'error');
        return;
    }

    if (newPassword.length < 8) {
        Portal.toast('Password must be at least 8 characters', 'error');
        return;
    }

    try {
        const response = await Portal.fetch('/api/me/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to change password');
        }

        Portal.toast('Password changed successfully');
        closeModal('profile-modal');
    } catch (error) {
        Portal.toast(error.message || 'Failed to change password', 'error');
        console.error('Change password error:', error);
    }
}


// =============================================================================
// Two-Factor Authentication Functions
// =============================================================================

/**
 * Load 2FA status when profile modal opens
 */
async function load2FAStatus() {
    const loadingEl = document.getElementById('2fa-status-loading');
    const enabledEl = document.getElementById('2fa-enabled-section');
    const disabledEl = document.getElementById('2fa-disabled-section');

    loadingEl.style.display = 'flex';
    enabledEl.style.display = 'none';
    disabledEl.style.display = 'none';

    try {
        const data = await Portal.fetchJSON('/api/user/2fa/status');
        loadingEl.style.display = 'none';

        if (data.enabled) {
            enabledEl.style.display = 'block';
            document.getElementById('backup-codes-count').textContent = data.backup_codes_remaining;
        } else {
            disabledEl.style.display = 'block';
        }
    } catch (error) {
        loadingEl.style.display = 'none';
        disabledEl.style.display = 'block';
        console.error('Failed to load 2FA status:', error);
    }
}

/**
 * Start 2FA setup process
 */
async function setup2FA() {
    try {
        const response = await Portal.fetch('/api/user/2fa/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to start 2FA setup');
        }

        const data = await response.json();

        // Display secret
        document.getElementById('2fa-secret-display').textContent = data.secret;

        // Generate QR code
        const canvas = document.getElementById('2fa-qr-canvas');
        if (typeof QRCode !== 'undefined') {
            QRCode.toCanvas(canvas, data.uri, { width: 200, margin: 1 }, function(error) {
                if (error) console.error('QR code generation error:', error);
            });
        } else {
            console.error('QRCode library not loaded');
            canvas.style.display = 'none';
        }

        // Reset and show setup modal
        document.getElementById('2fa-verify-code').value = '';
        document.getElementById('2fa-setup-step1').style.display = 'block';
        document.getElementById('2fa-setup-step2').style.display = 'none';
        showModal('2fa-setup-modal');

    } catch (error) {
        Portal.toast(error.message || 'Failed to start 2FA setup', 'error');
        console.error('2FA setup error:', error);
    }
}

/**
 * Verify 2FA setup code
 */
async function verify2FASetup() {
    const code = document.getElementById('2fa-verify-code').value.trim();
    if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
        Portal.toast('Please enter a valid 6-digit code', 'error');
        return;
    }

    try {
        const response = await Portal.fetch('/api/user/2fa/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Verification failed');
        }

        // Show backup codes
        const codesHtml = data.backup_codes.map(c => `<div>${c}</div>`).join('');
        document.getElementById('2fa-backup-codes').innerHTML = codesHtml;
        document.getElementById('2fa-setup-step1').style.display = 'none';
        document.getElementById('2fa-setup-step2').style.display = 'block';

        Portal.toast('2FA verification successful');

    } catch (error) {
        Portal.toast(error.message || 'Invalid verification code', 'error');
        console.error('2FA verify error:', error);
    }
}

/**
 * Finish 2FA setup
 */
function finish2FASetup() {
    closeModal('2fa-setup-modal');
    load2FAStatus();
    Portal.toast('Two-factor authentication enabled successfully');
}

/**
 * Show 2FA disable confirmation modal
 */
function show2FADisableModal() {
    document.getElementById('2fa-disable-form').reset();
    showModal('2fa-disable-modal');
}

/**
 * Disable 2FA
 */
async function disable2FA(event) {
    event.preventDefault();

    const password = document.getElementById('2fa-disable-password').value;

    try {
        const response = await Portal.fetch('/api/user/2fa/disable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: password })
        });

        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.error || 'Failed to disable 2FA');
        }

        closeModal('2fa-disable-modal');
        load2FAStatus();
        Portal.toast('Two-factor authentication disabled');

    } catch (error) {
        Portal.toast(error.message || 'Failed to disable 2FA', 'error');
        console.error('2FA disable error:', error);
    }
}



// Initialize admin UI when page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('admin.js DOMContentLoaded');
    initAdminUI();
});

console.log('admin.js loaded, functions defined:',
    typeof showAddServiceModal,
    typeof showManageUsersModal,
    typeof showInviteCode,
    typeof showLogsModal);

// Close modals on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(modal => {
            if (modal.style.display === 'flex') {
                closeModal(modal.id);
            }
        });
    }
});
