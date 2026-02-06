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

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Portal;
}
