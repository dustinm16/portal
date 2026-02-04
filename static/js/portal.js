/**
 * Portal Gateway - Shared JavaScript Utilities
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
            http_proxy: 'Web Interface',
            tcp_tunnel: 'TCP Tunnel',
            vpn_tunnel: 'VPN Tunnel'
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
            case 'http_proxy':
                // For HTTP proxy, connect to the service path directly
                window.open(service.path, '_blank');
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
        // Simple toast implementation
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
