/**
 * Open Relay Portal - Shared JavaScript Utilities
 */

const Portal = {
    /**
     * Get WebSocket URL for a given path
     */
    getWebSocketUrl(path) {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${protocol}//${location.host}${path}`;
    },

    /**
     * Fetch with credentials (includes session cookie)
     */
    async fetch(url, options = {}) {
        const response = await fetch(url, {
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                ...options.headers
            },
            ...options
        });

        if (response.status === 401) {
            // Session expired, redirect to login
            window.location.href = '/login';
            throw new Error('Session expired');
        }

        return response;
    },

    /**
     * Fetch JSON data
     */
    async fetchJSON(url, options = {}) {
        const response = await this.fetch(url, options);
        return response.json();
    },

    /**
     * Post JSON data
     */
    async postJSON(url, data) {
        return this.fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
    },

    /**
     * Generic API call (returns parsed JSON)
     */
    async api(url, options = {}) {
        return this.fetchJSON(url, options);
    },

    /**
     * Get list of services
     */
    async getServices() {
        const data = await this.fetchJSON('/api/services');
        return data.services || [];
    },

    /**
     * Get current user info
     */
    async getCurrentUser() {
        return this.fetchJSON('/api/me');
    },

    /**
     * Get service icon SVG based on plugin type
     */
    getServiceIcon(plugin) {
        const icons = {
            terminal: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>`,
            ssh: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
            </svg>`,
            vnc: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>`,
            http_proxy: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>`,
            tcp_tunnel: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
            </svg>`,
            vpn_tunnel: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>`,
            secure_tunnel: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>`,
            mediamtx: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>`,
            spice: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>`,
            proxmox: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>`,
            github: `<svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>`
        };

        return icons[plugin] || icons.tcp_tunnel;
    },

    /**
     * Get display name for plugin type
     */
    getPluginDisplayName(plugin) {
        const names = {
            terminal: 'Terminal',
            ssh: 'SSH',
            vnc: 'VNC Desktop',
            spice: 'SPICE Console',
            proxmox: 'Proxmox VE',
            http_proxy: 'Web Interface',
            tcp_tunnel: 'TCP Tunnel',
            vpn_tunnel: 'VPN Tunnel',
            secure_tunnel: 'Secure Tunnel',
            mediamtx: 'Media Stream',
            github: 'GitHub'
        };
        return names[plugin] || plugin;
    },

    /**
     * Open service in appropriate viewer
     */
    openService(service) {
        const plugin = service.plugin || 'tcp_tunnel';

        switch (plugin) {
            case 'terminal':
            case 'ssh':
                window.open(`/terminal/${service.id}`, '_blank', 'width=900,height=600');
                break;
            case 'vnc':
                window.open(`/vnc/${service.id}`, '_blank', 'width=1280,height=800');
                break;
            case 'spice':
                window.open(`/spice/${service.id}`, '_blank', 'width=1280,height=800');
                break;
            case 'proxmox':
                window.open(`/proxmox/${service.id}`, '_blank', 'width=1280,height=800');
                break;
            case 'mediamtx':
                window.open(`/media/${service.id}`, '_blank', 'width=1280,height=800');
                break;
            case 'github':
                window.open(`/github/${service.id}`, '_blank', 'width=1400,height=900');
                break;
            case 'http_proxy':
                // For HTTP proxy, validate and connect to the service path
                if (service.path && typeof service.path === 'string' && !service.path.includes('..')) {
                    window.open(service.path, '_blank');
                } else {
                    console.warn('Invalid http_proxy service path:', service.path);
                    Portal.toast('Invalid service path configuration', 'error');
                }
                break;
            default:
                console.warn(`Unknown plugin type: ${plugin}`);
                alert(`Service type "${plugin}" is not supported in the web UI`);
        }
    },

    /**
     * Format relative time
     */
    formatRelativeTime(date) {
        const now = new Date();
        const diff = now - new Date(date);
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return 'just now';
    },

    /**
     * Show toast notification
     */
    toast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 20px;
            background: ${type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(96, 165, 250, 0.9)'};
            color: white;
            border-radius: 8px;
            font-size: 14px;
            z-index: 9999;
            animation: slideIn 0.3s ease;
        `;

        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    /**
     * Format bytes to human readable
     */
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    /**
     * Format number with commas
     */
    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    /**
     * Session activity tracking
     */
    sessionActivity: {
        lastActivity: Date.now(),
        warningTimeout: null,
        expiryTimeout: null,
        sessionDuration: 24 * 60 * 60 * 1000,
        warningBefore: 5 * 60 * 1000,

        init(duration) {
            if (duration) this.sessionDuration = duration;
            this.resetActivity();
            this.setupListeners();
        },

        setupListeners() {
            ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
                document.addEventListener(event, () => this.resetActivity(), { passive: true });
            });
        },

        resetActivity() {
            this.lastActivity = Date.now();
            this.hideBanner();

            if (this.warningTimeout) clearTimeout(this.warningTimeout);
            if (this.expiryTimeout) clearTimeout(this.expiryTimeout);

            const timeUntilWarning = this.sessionDuration - this.warningBefore;
            this.warningTimeout = setTimeout(() => this.showWarning(), timeUntilWarning);
            this.expiryTimeout = setTimeout(() => this.sessionExpired(), this.sessionDuration);
        },

        showWarning() {
            let banner = document.getElementById('session-banner');
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'session-banner';
                banner.className = 'session-banner';
                banner.innerHTML = `
                    <span>Your session will expire soon due to inactivity.</span>
                    <button onclick="Portal.sessionActivity.resetActivity()">Stay Signed In</button>
                `;
                document.body.prepend(banner);
            }
            banner.classList.remove('hidden');
        },

        hideBanner() {
            const banner = document.getElementById('session-banner');
            if (banner) banner.classList.add('hidden');
        },

        sessionExpired() {
            window.location.href = '/login?expired=1';
        }
    }
};

// Navbar hamburger toggle
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.navbar-toggle');
    const menu = document.querySelector('.navbar-menu');
    if (toggle && menu) {
        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            menu.classList.toggle('open');
            toggle.setAttribute('aria-expanded', menu.classList.contains('open'));
        });
        document.addEventListener('click', (e) => {
            if (!menu.contains(e.target) && !toggle.contains(e.target)) {
                menu.classList.remove('open');
                toggle.setAttribute('aria-expanded', 'false');
            }
        });
    }
});

// Add CSS animations for toast
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Notification bell system
const NotificationBell = {
    _unreadCount: 0,
    _dropdown: null,
    _pollInterval: null,

    init() {
        // Find the navbar user link to inject bell before it
        const userLink = document.querySelector('.navbar-user');
        if (!userLink) return;

        // Create bell button
        const bell = document.createElement('a');
        bell.href = '#';
        bell.className = 'navbar-bell';
        bell.title = 'Notifications';
        bell.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="20" height="20">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            <span class="bell-badge" id="bell-badge" style="display: none;">0</span>
        `;
        bell.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.toggleDropdown();
        });
        userLink.parentNode.insertBefore(bell, userLink);

        // Create dropdown
        this._dropdown = document.createElement('div');
        this._dropdown.className = 'notification-dropdown';
        this._dropdown.style.display = 'none';
        this._dropdown.innerHTML = `
            <div class="notif-header">
                <span>Notifications</span>
                <a href="#" onclick="NotificationBell.markAllRead(); return false;">Mark all read</a>
            </div>
            <div class="notif-list" id="notif-list">
                <div class="notif-empty">No notifications</div>
            </div>
        `;
        document.body.appendChild(this._dropdown);

        // Close dropdown on outside click
        document.addEventListener('click', (e) => {
            if (!bell.contains(e.target) && !this._dropdown.contains(e.target)) {
                this._dropdown.style.display = 'none';
            }
        });

        // Load initial count
        this.loadCount();
        // Poll every 30s
        this._pollInterval = setInterval(() => this.loadCount(), 30000);
    },

    async loadCount() {
        try {
            const data = await Portal.api('/api/notifications?unread=1');
            this._unreadCount = data.unread_count || 0;
            this.updateBadge();
        } catch (e) { /* ignore */ }
    },

    updateBadge() {
        const badge = document.getElementById('bell-badge');
        if (!badge) return;
        if (this._unreadCount > 0) {
            badge.textContent = this._unreadCount > 99 ? '99+' : this._unreadCount;
            badge.style.display = 'flex';
        } else {
            badge.style.display = 'none';
        }
    },

    async toggleDropdown() {
        if (this._dropdown.style.display === 'none') {
            await this.loadNotifications();
            const bell = document.querySelector('.navbar-bell');
            const rect = bell.getBoundingClientRect();
            this._dropdown.style.top = rect.bottom + 4 + 'px';
            this._dropdown.style.right = (window.innerWidth - rect.right) + 'px';
            this._dropdown.style.display = 'block';
        } else {
            this._dropdown.style.display = 'none';
        }
    },

    async loadNotifications() {
        try {
            const data = await Portal.api('/api/notifications');
            const list = document.getElementById('notif-list');
            const notifications = data.notifications || [];
            if (notifications.length === 0) {
                list.innerHTML = '<div class="notif-empty">No notifications</div>';
                return;
            }
            list.innerHTML = notifications.slice(0, 20).map(n => {
                const timeAgo = Portal.formatRelativeTime ? Portal.formatRelativeTime(n.created_at) : '';
                const unreadClass = n.is_read ? '' : ' notif-unread';
                const dataStr = typeof n.data === 'string' ? n.data : JSON.stringify(n.data || {});
                const safeData = dataStr.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                return `<div class="notif-item${unreadClass}" onclick="NotificationBell.clickNotification(${n.id}, '${safeData}')">
                    <div class="notif-title">${this.escapeHtml(n.title)}</div>
                    <div class="notif-message">${this.escapeHtml(n.message || '')}</div>
                    <div class="notif-time">${timeAgo}</div>
                </div>`;
            }).join('');
        } catch (e) {
            console.error('Failed to load notifications:', e);
        }
    },

    async clickNotification(id, dataStr) {
        await this.markRead(id);
        try {
            const data = JSON.parse(dataStr);
            if (data.public_key) {
                window.open('/watch/' + data.public_key, '_blank');
            }
        } catch (e) { /* ignore */ }
    },

    async markRead(id) {
        try {
            await Portal.api(`/api/notifications/${id}/read`, { method: 'POST' });
            this._unreadCount = Math.max(0, this._unreadCount - 1);
            this.updateBadge();
            const item = this._dropdown.querySelector(`[onclick*="clickNotification(${id}"]`);
            if (item) item.classList.remove('notif-unread');
        } catch (e) { /* ignore */ }
    },

    async markAllRead() {
        try {
            await Portal.api('/api/notifications/read-all', { method: 'POST' });
            this._unreadCount = 0;
            this.updateBadge();
            this._dropdown.querySelectorAll('.notif-unread').forEach(el => el.classList.remove('notif-unread'));
        } catch (e) { /* ignore */ }
    },

    // Handle real-time notification push from WebSocket
    handlePush(notification) {
        this._unreadCount++;
        this.updateBadge();
        // Show toast
        Portal.toast(notification.title, 'info');
    },

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
};

// Auto-init notification bell on pages with navbar (skip login page)
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.navbar-user')) {
        NotificationBell.init();
    }
});

// Add notification bell CSS
const notifStyle = document.createElement('style');
notifStyle.textContent = `
    .navbar-bell {
        position: relative;
        display: flex;
        align-items: center;
        padding: 0.25rem;
    }
    .bell-badge {
        position: absolute;
        top: -4px;
        right: -4px;
        background: var(--accent-red, #ef4444);
        color: white;
        font-size: 0.625rem;
        font-weight: 700;
        min-width: 16px;
        height: 16px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 0 3px;
    }
    .notification-dropdown {
        position: fixed;
        z-index: 10002;
        width: min(320px, calc(100vw - 1rem));
        max-height: 400px;
        background: var(--bg-secondary, #1e1e2e);
        border: 1px solid var(--card-border, rgba(255,255,255,0.1));
        border-radius: 8px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        overflow: hidden;
    }
    .notif-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 1rem;
        border-bottom: 1px solid var(--card-border, rgba(255,255,255,0.1));
        font-weight: 600;
        font-size: 0.875rem;
    }
    .notif-header a {
        font-size: 0.75rem;
        font-weight: 400;
        color: var(--accent-blue, #60a5fa);
    }
    .notif-list {
        max-height: 340px;
        overflow-y: auto;
    }
    .notif-item {
        padding: 0.75rem 1rem;
        border-bottom: 1px solid var(--card-border, rgba(255,255,255,0.05));
        cursor: pointer;
        transition: background 0.15s;
    }
    .notif-item:hover {
        background: var(--card-hover, rgba(255,255,255,0.05));
    }
    .notif-unread {
        border-left: 3px solid var(--accent-blue, #60a5fa);
    }
    .notif-title {
        font-weight: 600;
        font-size: 0.8125rem;
        margin-bottom: 2px;
    }
    .notif-message {
        font-size: 0.75rem;
        color: var(--text-muted, #888);
    }
    .notif-time {
        font-size: 0.6875rem;
        color: var(--text-muted, #666);
        margin-top: 4px;
    }
    .notif-empty {
        padding: 2rem;
        text-align: center;
        color: var(--text-muted, #888);
        font-size: 0.875rem;
    }
`;
document.head.appendChild(notifStyle);

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Portal;
}
