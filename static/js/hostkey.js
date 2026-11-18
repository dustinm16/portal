/**
 * Open Relay Portal - SSH host key prompt
 *
 * Shows the fingerprint of a server's SSH host key when the portal refused a
 * connection because the key is not trusted yet ("unpinned") or differs from
 * the one accepted earlier ("changed"). Only a user the server marked
 * can_accept (the connection's owner, or an admin for a service) gets an
 * Accept button; accepting is an authenticated HTTP request to accept_url.
 * Used by the terminal page, the file browser and the VOD storage settings.
 */
const HostKey = (() => {
    function el(tag, attrs, text) {
        const e = document.createElement(tag);
        if (attrs) Object.keys(attrs).forEach(k => { e.style[k] = attrs[k]; });
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function notify(msg, type) {
        if (typeof Portal !== 'undefined' && Portal.toast) Portal.toast(msg, type);
        else if (typeof showToast === 'function') showToast(msg, type);
    }

    function fingerprintBox(label, value) {
        const box = el('div', { marginBottom: '0.75rem' });
        box.appendChild(el('div', { fontSize: '0.8rem', color: 'var(--text-muted, #8b949e)' }, label));
        box.appendChild(el('div', {
            fontFamily: 'monospace', fontSize: '0.85rem', wordBreak: 'break-all',
            padding: '0.5rem', borderRadius: '6px', background: 'rgba(127,127,127,0.12)',
            userSelect: 'all'
        }, value || ''));
        return box;
    }

    /**
     * info: {state, fingerprint, expected, can_accept, accept_url, host, port, accept_token, message}
     * opts: {onAccepted(fingerprint)}
     */
    function prompt(info, opts) {
        const options = opts || {};
        const existing = document.getElementById('hostkey-dialog');
        if (existing) existing.remove();

        const changed = info.state === 'changed';
        const overlay = el('div', {
            position: 'fixed', top: '0', left: '0', right: '0', bottom: '0', zIndex: '10000',
            display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.6)'
        });
        overlay.id = 'hostkey-dialog';
        const card = el('div', {
            maxWidth: '34rem', width: '92%', padding: '1.25rem', borderRadius: '10px',
            background: 'var(--bg-secondary, #161b22)', color: 'var(--text-primary, #c9d1d9)',
            border: '1px solid ' + (changed ? '#ef4444' : 'var(--border-color, #30363d)')
        });
        card.setAttribute('role', 'dialog');
        card.appendChild(el('h3', { marginTop: '0', color: changed ? '#ef4444' : 'inherit' },
            changed ? 'Host key changed' : 'Confirm host key'));
        card.appendChild(el('p', { fontSize: '0.9rem' }, info.message || ''));
        if (changed && info.expected) card.appendChild(fingerprintBox('Accepted earlier', info.expected));
        card.appendChild(fingerprintBox(changed ? 'Presented now' : 'Fingerprint (SHA256)', info.fingerprint));
        if (info.algorithm) {
            card.appendChild(el('p', { fontSize: '0.8rem', color: 'var(--text-muted, #8b949e)' },
                'Key type: ' + info.algorithm));
        }

        const actions = el('div', { display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' });
        const close = el('button', null, info.can_accept ? 'Cancel' : 'Close');
        close.className = 'btn btn-secondary';
        close.type = 'button';
        close.addEventListener('click', () => overlay.remove());
        actions.appendChild(close);

        if (info.can_accept && info.accept_url) {
            const accept = el('button', null, changed ? 'Accept new key' : 'Accept this key');
            accept.className = changed ? 'btn btn-danger' : 'btn btn-primary';
            accept.type = 'button';
            accept.addEventListener('click', async () => {
                accept.disabled = true;
                try {
                    const res = await Portal.fetch(info.accept_url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            fingerprint: info.fingerprint, host: info.host, port: info.port, token: info.accept_token
                        })
                    });
                    const body = await res.json().catch(() => ({}));
                    if (!res.ok) {
                        notify(body.error || 'Could not accept the host key', 'error');
                        accept.disabled = false;
                        return;
                    }
                    notify('Host key accepted', 'success');
                    overlay.remove();
                    if (options.onAccepted) options.onAccepted(info.fingerprint);
                } catch (e) {
                    notify('Could not accept the host key', 'error');
                    accept.disabled = false;
                }
            });
            actions.appendChild(accept);
        }
        card.appendChild(actions);
        overlay.appendChild(card);
        overlay.addEventListener('click', (ev) => { if (ev.target === overlay) overlay.remove(); });
        document.body.appendChild(overlay);
    }

    return { prompt };
})();
