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

/**
 * Show Add Service Modal
 */
function showAddServiceModal() {
    console.log('showAddServiceModal called');
    document.getElementById('add-service-form').reset();
    showModal('add-service-modal');
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

        renderUsersTable(data.users);
        console.log('Users table rendered');
    } catch (error) {
        Portal.toast(error.message || 'Failed to load users', 'error');
        console.error('Load users error:', error);
        document.getElementById('users-loading').style.display = 'none';
    }
}

/**
 * Render users table
 */
function renderUsersTable(users) {
    console.log('renderUsersTable called with', users?.length, 'users');
    const tbody = document.getElementById('users-tbody');
    console.log('tbody element:', tbody);

    tbody.innerHTML = users.map(user => `
        <tr data-user-id="${user.id}">
            <td>${user.id}</td>
            <td>${escapeHtml(user.username)}</td>
            <td>
                <label class="toggle">
                    <input type="checkbox"
                           ${user.is_admin ? 'checked' : ''}
                           ${user.id === currentUser.id ? 'disabled' : ''}
                           onchange="toggleUserAdmin(${user.id}, this.checked)">
                    <span class="toggle-slider"></span>
                </label>
            </td>
            <td>${formatDate(user.created_at)}</td>
            <td>
                ${user.id !== currentUser.id ? `
                    <button class="btn btn-danger btn-sm" onclick="confirmDeleteUser(${user.id}, '${escapeHtml(user.username)}')">
                        Delete
                    </button>
                ` : '<span style="color: var(--text-muted);">Current user</span>'}
            </td>
        </tr>
    `).join('');

    document.getElementById('users-loading').style.display = 'none';
    document.getElementById('users-table').style.display = 'table';
}

/**
 * Toggle user admin status
 */
async function toggleUserAdmin(userId, isAdmin) {
    try {
        const response = await Portal.fetch(`/api/users/${userId}/admin`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_admin: isAdmin })
        });

        if (response.ok) {
            const action = isAdmin ? 'granted' : 'revoked';
            Portal.toast(`Admin status ${action}`);
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update user', 'error');
            // Revert checkbox
            const checkbox = document.querySelector(`tr[data-user-id="${userId}"] input[type="checkbox"]`);
            if (checkbox) checkbox.checked = !isAdmin;
        }
    } catch (error) {
        Portal.toast('Failed to update user', 'error');
        console.error('Toggle admin error:', error);
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
