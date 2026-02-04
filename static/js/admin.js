/**
 * Portal Gateway - Admin Functions
 */

let currentUser = null;
let pendingConfirmAction = null;

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
    document.getElementById(modalId).style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

/**
 * Close modal by ID
 */
function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    document.body.style.overflow = '';
}

/**
 * Show Add Service Modal
 */
function showAddServiceModal() {
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
    showModal('manage-users-modal');
    document.getElementById('users-loading').style.display = 'flex';
    document.getElementById('users-table').style.display = 'none';

    try {
        const response = await Portal.fetch('/api/users');
        const data = await response.json();

        renderUsersTable(data.users);
    } catch (error) {
        Portal.toast('Failed to load users', 'error');
        console.error('Load users error:', error);
    }
}

/**
 * Render users table
 */
function renderUsersTable(users) {
    const tbody = document.getElementById('users-tbody');

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
    showModal('invite-code-modal');
    document.getElementById('invite-code-display').textContent = 'Loading...';

    try {
        const response = await Portal.fetch('/api/invite-code');
        const data = await response.json();

        document.getElementById('invite-code-display').textContent = data.code;
    } catch (error) {
        document.getElementById('invite-code-display').textContent = 'Error loading code';
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

// Initialize admin UI when page loads
document.addEventListener('DOMContentLoaded', initAdminUI);

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
