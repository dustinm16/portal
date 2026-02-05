/**
 * Portal Gateway - User Streams Management
 * Handles OBS streaming, stream key management, and community streams.
 */

// Current stream being viewed
let currentStreamId = null;
let streamChatWs = null;

/**
 * Load user's streams
 */
async function loadUserStreams() {
    const loadingEl = document.getElementById('streams-loading');
    const gridEl = document.getElementById('streams-grid');
    const emptyEl = document.getElementById('streams-empty');

    if (!loadingEl || !gridEl || !emptyEl) return;

    loadingEl.style.display = 'flex';
    gridEl.style.display = 'none';
    emptyEl.style.display = 'none';

    try {
        const data = await Portal.fetchJSON('/api/streams');
        const streams = data.streams || [];

        loadingEl.style.display = 'none';

        if (streams.length === 0) {
            emptyEl.style.display = 'flex';
            return;
        }

        gridEl.style.display = 'grid';
        gridEl.innerHTML = streams.map(stream => renderStreamCard(stream, true)).join('');

    } catch (error) {
        console.error('Failed to load streams:', error);
        loadingEl.style.display = 'none';
        gridEl.innerHTML = `<div class="error-message">Failed to load streams: ${error.message}</div>`;
        gridEl.style.display = 'block';
    }
}

/**
 * Load community (public) streams
 */
async function loadCommunityStreams() {
    const loadingEl = document.getElementById('community-streams-loading');
    const gridEl = document.getElementById('community-streams-grid');
    const emptyEl = document.getElementById('community-streams-empty');

    if (!loadingEl || !gridEl || !emptyEl) return;

    loadingEl.style.display = 'flex';
    gridEl.style.display = 'none';
    emptyEl.style.display = 'none';

    try {
        const data = await Portal.fetchJSON('/api/streams/public');
        const streams = data.streams || [];

        loadingEl.style.display = 'none';

        if (streams.length === 0) {
            emptyEl.style.display = 'flex';
            return;
        }

        gridEl.style.display = 'grid';
        gridEl.innerHTML = streams.map(stream => renderStreamCard(stream, false)).join('');

    } catch (error) {
        console.error('Failed to load community streams:', error);
        loadingEl.style.display = 'none';
        gridEl.innerHTML = `<div class="error-message">Failed to load streams: ${error.message}</div>`;
        gridEl.style.display = 'block';
    }
}

/**
 * Render a stream card
 */
function renderStreamCard(stream, isOwner = false) {
    const statusClass = stream.is_live ? 'status-live' : 'status-offline';
    const statusText = stream.is_live ? 'LIVE' : 'Offline';
    const viewerCount = stream.is_live ? `${stream.viewer_count || 0} viewers` : '';
    const publicBadge = stream.is_public ? '<span class="badge badge-public">Public</span>' : '<span class="badge badge-private">Private</span>';

    if (isOwner) {
        return `
            <div class="connection-card stream-card ${stream.is_live ? 'stream-live' : ''}">
                <div class="connection-header">
                    <div class="connection-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                    </div>
                    <div class="connection-info">
                        <h4>${escapeHtml(stream.name)}</h4>
                        <span class="connection-type">
                            <span class="stream-status ${statusClass}">${statusText}</span>
                            ${viewerCount}
                        </span>
                    </div>
                    ${publicBadge}
                </div>
                ${stream.description ? `<p class="stream-description">${escapeHtml(stream.description)}</p>` : ''}
                <div class="connection-actions">
                    <button class="btn btn-sm btn-primary" onclick="showStreamDetails(${stream.id})">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                        Stream Key
                    </button>
                    <button class="btn btn-sm btn-secondary" onclick="editStream(${stream.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteStream(${stream.id})">Delete</button>
                </div>
            </div>
        `;
    } else {
        // Community stream card
        return `
            <div class="connection-card stream-card ${stream.is_live ? 'stream-live' : ''}" onclick="viewStream(${stream.id})" style="cursor: pointer;">
                <div class="connection-header">
                    <div class="connection-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                    </div>
                    <div class="connection-info">
                        <h4>${escapeHtml(stream.name)}</h4>
                        <span class="connection-type">
                            by ${escapeHtml(stream.owner_username || 'Unknown')}
                        </span>
                    </div>
                    <span class="stream-status ${statusClass}">${statusText}</span>
                </div>
                ${stream.description ? `<p class="stream-description">${escapeHtml(stream.description)}</p>` : ''}
                <div class="stream-meta">
                    ${stream.is_live ? `<span class="viewer-count">${stream.viewer_count || 0} watching</span>` : ''}
                    <span class="total-views">${stream.total_views || 0} total views</span>
                </div>
            </div>
        `;
    }
}

/**
 * Show create stream modal
 */
function showCreateStreamModal() {
    document.getElementById('create-stream-form').reset();
    openModal('create-stream-modal');
}

/**
 * Create a new stream
 */
async function createStream(event) {
    event.preventDefault();

    const name = document.getElementById('stream-name').value.trim();
    const description = document.getElementById('stream-description').value.trim();
    const isPublic = document.getElementById('stream-public').checked;

    if (!name) {
        alert('Stream name is required');
        return;
    }

    try {
        const response = await Portal.postJSON('/api/streams', {
            name,
            description,
            is_public: isPublic
        });

        if (response.ok) {
            closeModal('create-stream-modal');
            loadUserStreams();
            const data = await response.json();
            // Show the stream key
            showStreamDetails(data.stream.id);
        } else {
            const error = await response.json();
            alert(error.error || 'Failed to create stream');
        }
    } catch (error) {
        console.error('Failed to create stream:', error);
        alert('Failed to create stream');
    }
}

/**
 * Show stream details (stream key)
 */
async function showStreamDetails(streamId) {
    currentStreamId = streamId;

    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}`);
        const stream = data.stream;

        document.getElementById('stream-details-title').textContent = stream.name;

        const rtmpUrl = `rtmps://${window.location.hostname}:1936/live`;
        const rtspUrl = `rtsps://${window.location.hostname}:8322/${stream.stream_key}`;

        document.getElementById('stream-details-content').innerHTML = `
            <div class="stream-details">
                <div class="info-section">
                    <h4>Stream Status</h4>
                    <p class="stream-status ${stream.is_live ? 'status-live' : 'status-offline'}">
                        ${stream.is_live ? 'LIVE' : 'Offline'}
                        ${stream.is_live ? `(${stream.viewer_count || 0} viewers)` : ''}
                    </p>
                </div>

                <div class="info-section">
                    <h4>OBS Settings</h4>
                    <p class="info-description">Use these settings in OBS Studio to start streaming.</p>

                    <div class="form-group">
                        <label>Server (RTMPS)</label>
                        <div class="input-with-copy">
                            <input type="text" value="${rtmpUrl}" readonly>
                            <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${rtmpUrl}')">Copy</button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Stream Key</label>
                        <div class="input-with-copy">
                            <input type="password" value="${stream.stream_key}" readonly id="stream-key-input">
                            <button class="btn btn-sm btn-secondary" onclick="toggleStreamKeyVisibility()">Show</button>
                            <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${stream.stream_key}')">Copy</button>
                        </div>
                        <small class="warning-text">Keep your stream key secret! Anyone with this key can stream to your channel.</small>
                    </div>
                </div>

                <div class="info-section">
                    <h4>Stream Settings</h4>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" ${stream.is_public ? 'checked' : ''} onchange="toggleStreamPublic(${stream.id}, this.checked)">
                            <span>Public stream (visible to all users)</span>
                        </label>
                    </div>
                </div>

                <div class="info-section">
                    <h4>Playback URLs</h4>
                    <div class="form-group">
                        <label>HLS (for web players)</label>
                        <div class="input-with-copy">
                            <input type="text" value="https://${window.location.hostname}:8888/${stream.stream_key}/index.m3u8" readonly>
                            <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('https://${window.location.hostname}:8888/${stream.stream_key}/index.m3u8')">Copy</button>
                        </div>
                    </div>
                </div>

                <div class="form-actions">
                    <button class="btn btn-warning" onclick="regenerateStreamKey(${stream.id})">Regenerate Key</button>
                    <button class="btn btn-secondary" onclick="closeModal('stream-details-modal')">Close</button>
                </div>
            </div>
        `;

        openModal('stream-details-modal');

    } catch (error) {
        console.error('Failed to load stream details:', error);
        alert('Failed to load stream details');
    }
}

/**
 * Toggle stream key visibility
 */
function toggleStreamKeyVisibility() {
    const input = document.getElementById('stream-key-input');
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        // Could show a toast notification here
    } catch (error) {
        console.error('Failed to copy:', error);
    }
}

/**
 * Toggle stream public/private
 */
async function toggleStreamPublic(streamId, isPublic) {
    try {
        const response = await fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ is_public: isPublic })
        });

        if (!response.ok) {
            const error = await response.json();
            alert(error.error || 'Failed to update stream');
        } else {
            loadUserStreams();
        }
    } catch (error) {
        console.error('Failed to update stream:', error);
        alert('Failed to update stream');
    }
}

/**
 * Regenerate stream key
 */
async function regenerateStreamKey(streamId) {
    if (!confirm('Are you sure? This will invalidate your current stream key.')) {
        return;
    }

    try {
        const response = await fetch(`/api/streams/${streamId}/regenerate-key`, {
            method: 'POST',
            credentials: 'same-origin'
        });

        if (response.ok) {
            showStreamDetails(streamId);
        } else {
            const error = await response.json();
            alert(error.error || 'Failed to regenerate key');
        }
    } catch (error) {
        console.error('Failed to regenerate key:', error);
        alert('Failed to regenerate key');
    }
}

/**
 * Edit stream
 */
async function editStream(streamId) {
    // For now, just show details. Could add a dedicated edit modal later.
    showStreamDetails(streamId);
}

/**
 * Delete stream
 */
async function deleteStream(streamId) {
    if (!confirm('Are you sure you want to delete this stream?')) {
        return;
    }

    try {
        const response = await fetch(`/api/streams/${streamId}`, {
            method: 'DELETE',
            credentials: 'same-origin'
        });

        if (response.ok) {
            loadUserStreams();
        } else {
            const error = await response.json();
            alert(error.error || 'Failed to delete stream');
        }
    } catch (error) {
        console.error('Failed to delete stream:', error);
        alert('Failed to delete stream');
    }
}

/**
 * View a community stream
 */
async function viewStream(streamId) {
    currentStreamId = streamId;

    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}`);
        const stream = data.stream;

        if (!stream.is_live) {
            alert('This stream is currently offline');
            return;
        }

        document.getElementById('view-stream-title').textContent = `${stream.name} - ${stream.owner_username}`;

        // Set up video player with HLS
        const video = document.getElementById('stream-video');
        const hlsUrl = `https://${window.location.hostname}:8888/${stream.stream_key}/index.m3u8`;

        if (video.canPlayType('application/vnd.apple.mpegurl')) {
            video.src = hlsUrl;
        } else if (typeof Hls !== 'undefined' && Hls.isSupported()) {
            const hls = new Hls();
            hls.loadSource(hlsUrl);
            hls.attachMedia(video);
        } else {
            alert('HLS playback not supported in your browser');
            return;
        }

        // Connect to chat if available
        if (stream.chat_channel_id) {
            connectStreamChat(stream.chat_channel_id);
        }

        openModal('view-stream-modal');

    } catch (error) {
        console.error('Failed to load stream:', error);
        alert('Failed to load stream');
    }
}

/**
 * Connect to stream chat
 */
function connectStreamChat(channelId) {
    if (streamChatWs) {
        streamChatWs.close();
    }

    const wsUrl = Portal.getWebSocketUrl(`/ws/chat/${channelId}`);
    streamChatWs = new WebSocket(wsUrl);

    streamChatWs.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'message') {
            appendStreamChatMessage(data);
        } else if (data.type === 'history') {
            document.getElementById('stream-chat-messages').innerHTML = '';
            data.messages.forEach(msg => appendStreamChatMessage(msg));
        }
    };

    streamChatWs.onclose = () => {
        streamChatWs = null;
    };
}

/**
 * Append a chat message to the stream chat
 */
function appendStreamChatMessage(msg) {
    const messagesEl = document.getElementById('stream-chat-messages');
    const messageEl = document.createElement('div');
    messageEl.className = 'chat-message';
    messageEl.innerHTML = `
        <span class="chat-username">${escapeHtml(msg.username)}</span>
        <span class="chat-text">${escapeHtml(msg.message)}</span>
    `;
    messagesEl.appendChild(messageEl);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

/**
 * Send a message to stream chat
 */
function sendStreamChatMessage(event) {
    event.preventDefault();

    const input = document.getElementById('stream-chat-input');
    const message = input.value.trim();

    if (!message || !streamChatWs) return;

    streamChatWs.send(JSON.stringify({
        type: 'message',
        message: message
    }));

    input.value = '';
}

/**
 * Escape HTML entities
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Load streams when tab is switched
const originalSwitchTab = window.switchTab;
window.switchTab = function(tab) {
    if (typeof originalSwitchTab === 'function') {
        originalSwitchTab(tab);
    }

    if (tab === 'my-streams') {
        loadUserStreams();
    } else if (tab === 'community-streams') {
        loadCommunityStreams();
    }
};

// Clean up when modal is closed
const originalCloseModal = window.closeModal;
window.closeModal = function(modalId) {
    if (modalId === 'view-stream-modal' && streamChatWs) {
        streamChatWs.close();
        streamChatWs = null;
    }

    if (typeof originalCloseModal === 'function') {
        originalCloseModal(modalId);
    } else {
        document.getElementById(modalId).style.display = 'none';
    }
};
