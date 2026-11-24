/**
 * Open Relay Portal - User Streams Management
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
        gridEl.innerHTML = `<div class="error-message">Failed to load streams: ${escapeHtml(error.message)}</div>`;
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
        gridEl.innerHTML = `<div class="error-message">Failed to load streams: ${escapeHtml(error.message)}</div>`;
        gridEl.style.display = 'block';
    }
}

/**
 * Render a stream card
 */
function renderStreamCard(stream, isOwner = false) {
    const isEncoding = stream.is_live === 2;
    const isLive = stream.is_live === 1;
    const statusClass = isLive ? 'live' : isEncoding ? 'encoding' : 'offline';
    const statusText = isLive ? 'LIVE' : isEncoding ? 'Encoding' : 'Offline';
    const viewerCount = isLive ? `${stream.viewer_count || 0} viewers` : '';
    const publicBadge = stream.is_public ? '<span class="badge badge-public">Public</span>' : '<span class="badge badge-private">Private</span>';

    // Thumbnail URL - use dynamic thumbnail for live streams, static for offline
    let thumbnailUrl = stream.thumbnail_url;
    if (isLive && stream.public_key) {
        // Use dynamic thumbnail from HLS stream (with cache buster)
        const cacheBuster = Math.floor(Date.now() / 15000); // Changes every 15 seconds
        thumbnailUrl = `/api/stream/${stream.public_key}/thumbnail?t=${cacheBuster}`;
    }

    // Thumbnail HTML - show image if available, otherwise show placeholder
    const thumbnailHtml = thumbnailUrl
        ? `<img src="${escapeHtml(thumbnailUrl)}" alt="Stream thumbnail" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
           <div class="stream-thumbnail-placeholder" style="display: none;">
               <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                   <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
               </svg>
           </div>`
        : `<div class="stream-thumbnail-placeholder">
               <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                   <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" />
               </svg>
           </div>`;

    if (isOwner) {
        return `
            <div class="connection-card stream-card has-thumbnail ${isLive ? 'stream-live' : isEncoding ? 'stream-encoding' : 'stream-offline'}">
                <div class="stream-thumbnail">
                    ${thumbnailHtml}
                    ${isLive ? '<div class="stream-live-badge"><span class="pulse"></span>LIVE</div>' : isEncoding ? '<div class="stream-encoding-badge"><span class="encoding-spinner"></span>ENCODING</div>' : '<div class="stream-offline-badge">OFFLINE</div>'}
                </div>
                <div class="stream-card-content">
                    <div class="connection-header">
                        <div class="connection-info">
                            <h4>${escapeHtml(stream.name)}</h4>
                            <span class="connection-type">
                                <span class="stream-status ${statusClass}">${statusText}</span>
                                ${viewerCount}
                            </span>
                        </div>
                        ${publicBadge}
                    </div>
                    ${stream.game ? `<p class="stream-description stream-game">${escapeHtml(stream.game)}</p>` : ''}
                    ${stream.description ? `<p class="stream-description">${escapeHtml(stream.description)}</p>` : ''}
                    <div class="connection-actions">
                        <button class="btn btn-sm btn-primary" onclick="viewStreamNewWindow('${escapeHtml(stream.public_key || '')}', event)">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Watch
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="showStreamDetails(${stream.id})">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="14" height="14">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                            </svg>
                            Manage
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteStream(${stream.id})">Delete</button>
                    </div>
                </div>
            </div>
        `;
    } else {
        // Community stream card
        return `
            <div class="connection-card stream-card has-thumbnail ${isLive ? 'stream-live' : isEncoding ? 'stream-encoding' : 'stream-offline'}" onclick="viewStream('${escapeHtml(stream.public_key || '')}')" style="cursor: pointer;">
                <div class="stream-thumbnail">
                    ${thumbnailHtml}
                    ${isLive ? '<div class="stream-live-badge"><span class="pulse"></span>LIVE</div>' : isEncoding ? '<div class="stream-encoding-badge"><span class="encoding-spinner"></span>ENCODING</div>' : '<div class="stream-offline-badge">OFFLINE</div>'}
                    ${isLive ? `<div class="stream-viewers"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" width="12" height="12"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>${stream.viewer_count || 0}</div>` : ''}
                </div>
                <div class="stream-card-content">
                    <div class="connection-header">
                        <div class="connection-info">
                            <h4>${escapeHtml(stream.name)}</h4>
                            <span class="connection-type">
                                by ${escapeHtml(stream.owner_nickname || stream.owner_username || 'Unknown')}
                            </span>
                        </div>
                    </div>
                    ${stream.game ? `<p class="stream-description stream-game">${escapeHtml(stream.game)}</p>` : ''}
                    ${stream.description ? `<p class="stream-description">${escapeHtml(stream.description)}</p>` : ''}
                    <div class="stream-meta">
                        <span class="total-views">${stream.total_views || 0} views</span>
                    </div>
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
    showModal('create-stream-modal');
    loadGameSuggestions('create-stream-game-list');
}

/**
 * Create a new stream
 */
async function createStream(event) {
    event.preventDefault();

    const name = document.getElementById('stream-name').value.trim();
    const description = document.getElementById('stream-description').value.trim();
    const game = document.getElementById('stream-game').value.trim();
    const isPublic = document.getElementById('stream-public').checked;
    const submitBtn = event.target.querySelector('button[type="submit"]');

    if (!name) {
        Portal.toast('Stream name is required', 'error');
        return;
    }

    Portal.setButtonLoading(submitBtn, true);
    try {
        const response = await Portal.postJSON('/api/streams', {
            name,
            description,
            game,
            is_public: isPublic
        });

        if (response.ok) {
            Portal.flashButtonSuccess(submitBtn);
            Portal.toast('Stream created', 'success');
            setTimeout(() => closeModal('create-stream-modal'), 800);
            loadUserStreams();
            const data = await response.json().catch(() => ({}));
            if (data.stream) showStreamDetails(data.stream.id);
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to create stream', 'error');
        }
    } catch (error) {
        console.error('Failed to create stream:', error);
        Portal.toast('Failed to create stream', 'error');
    } finally {
        Portal.setButtonLoading(submitBtn, false);
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

        // RTMPS publish URL (direct connection, bypasses CDN if applicable)
        const rtmpUrl = `rtmps://${window.location.hostname}:1936/live`;
        // HLS playback through Portal proxy on 443 (use public_key for viewing)
        const viewKey = stream.public_key || stream.stream_key;
        const hlsUrl = `https://${window.location.hostname}/api/stream/${viewKey}/hls/index.m3u8`;

        const thumbnailHtml = stream.thumbnail_url
            ? `<img src="${escapeHtml(stream.thumbnail_url)}" alt="Thumbnail">`
            : `<div class="upload-placeholder">
                   <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                       <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                   </svg>
                   <div>Click to upload thumbnail</div>
               </div>`;

        document.getElementById('stream-details-content').innerHTML = `
            <div class="stream-details">
                <div class="info-section">
                    <h4>Stream Status</h4>
                    <p class="stream-status ${stream.is_live === 1 ? 'live' : stream.is_live === 2 ? 'encoding' : 'offline'}">
                        ${stream.is_live === 1 ? 'LIVE' : stream.is_live === 2 ? 'Encoding VODs...' : 'Offline'}
                        ${stream.is_live === 1 ? `(${stream.viewer_count || 0} viewers)` : ''}
                    </p>
                    ${stream.last_peak_viewers != null ? `<p class="info-description">Last session: peak ${stream.last_peak_viewers}, ${stream.last_unique_viewers != null ? stream.last_unique_viewers : 0} unique viewers</p>` : ''}
                </div>

                <div class="info-section">
                    <h4>Thumbnail</h4>
                    <p class="info-description">Upload an image to show when your stream is offline.</p>
                    <div class="thumbnail-upload-area ${stream.thumbnail_url ? 'has-thumbnail' : ''}" onclick="document.getElementById('thumbnail-input').click()">
                        ${thumbnailHtml}
                    </div>
                    <input type="file" id="thumbnail-input" accept="image/*" style="display: none;" onchange="uploadThumbnail(${stream.id}, this)">
                    <div class="upload-hint">Max 5MB. Recommended 1280x720 (16:9)</div>
                    ${stream.thumbnail_url ? `<button class="btn btn-sm btn-danger" style="margin-top: 0.5rem;" onclick="deleteThumbnail(${stream.id})">Remove Thumbnail</button>` : ''}
                </div>

                <div class="info-section">
                    <h4>OBS Settings</h4>
                    <p class="info-description">Use these settings in OBS Studio to start streaming.</p>

                    <div class="form-group">
                        <label>Server (RTMPS)</label>
                        <div class="input-with-copy">
                            <input type="text" value="${rtmpUrl}" readonly>
                            <button class="btn btn-sm btn-secondary" data-copy="rtmp-url">Copy</button>
                        </div>
                        <small style="color: var(--text-muted);">Direct connection to streaming server</small>
                    </div>

                    <div class="form-group">
                        <label>Stream Key</label>
                        <div class="input-with-copy">
                            <input type="password" value="${stream.stream_key}" readonly id="stream-key-input">
                            <button class="btn btn-sm btn-secondary" onclick="toggleStreamKeyVisibility()">Show</button>
                            <button class="btn btn-sm btn-secondary" data-copy="stream-key">Copy</button>
                        </div>
                        <small class="warning-text">Keep your stream key secret! Anyone with this key can stream to your channel.</small>
                    </div>
                </div>

                <div class="info-section">
                    <h4>Stream health</h4>
                    <p class="info-description">What the server receives from your encoder while you stream: bitrate, relays, recording and warnings. Opens on the watch page; only you and administrators can see it.</p>
                    ${stream.public_key ? `<a class="btn btn-sm btn-secondary" id="stream-health-link" target="_blank" rel="noopener" href="/watch/${encodeURIComponent(stream.public_key)}#health">Open stream health</a>` : ''}
                </div>

                <div class="info-section">
                    <h4>Stream Settings</h4>
                    <div class="form-group">
                        <label>Stream Name</label>
                        <div class="input-with-copy">
                            <input type="text" id="stream-name-input" value="${escapeHtml(stream.name)}" maxlength="100">
                            <button id="save-name-btn" class="btn btn-sm btn-primary" onclick="updateStreamName(${stream.id})">Save</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <div class="input-with-copy">
                            <input type="text" id="stream-description-input" value="${escapeHtml(stream.description || '')}" maxlength="500" placeholder="Optional description">
                            <button id="save-description-btn" class="btn btn-sm btn-primary" onclick="updateStreamDescription(${stream.id})">Save</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Game</label>
                        <div class="input-with-copy">
                            <input type="text" id="stream-game-input" maxlength="60" list="stream-game-list" placeholder="Optional, shown next to the title" autocomplete="off">
                            <datalist id="stream-game-list"></datalist>
                            <button id="save-game-btn" class="btn btn-sm btn-primary" onclick="updateStreamGame(${stream.id})">Save</button>
                        </div>
                        <small>Up to 60 characters. Viewers see the title and game change at once while you are live.</small>
                    </div>
                    <div class="form-group">
                        <label>Go-live message</label>
                        <div class="input-with-copy">
                            <input type="text" id="stream-golive-input" maxlength="200" placeholder="{title} just went live">
                            <button id="save-golive-btn" class="btn btn-sm btn-primary" onclick="updateStreamGoLiveMessage(${stream.id})">Save</button>
                        </div>
                        <small>Plain text, up to 200 characters. You can use {streamer}, {title}, {game} and {url}; anything else is shown as typed. Sent once per 10 minutes when you go live. Leave empty for the default.</small>
                    </div>
                    <div class="form-group">
                        <label>Who is told when you go live</label>
                        <select id="stream-golive-audience" onchange="updateStreamGoLiveAudience(${stream.id}, this.value)">
                            <option value="followers">Members who follow this stream</option>
                            <option value="everyone">Every member who can watch it</option>
                        </select>
                        <small>${Number(stream.follower_count) || 0} ${Number(stream.follower_count) === 1 ? 'member follows' : 'members follow'} this stream (a number only: who follows is private). A notification goes only to members who can watch the stream at that moment, never to you.</small>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" ${stream.is_public ? 'checked' : ''} onchange="toggleStreamPublic(${stream.id}, this.checked)">
                            <span>Public stream (visible to all users)</span>
                        </label>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" ${stream.allow_unauthenticated ? 'checked' : ''} onchange="toggleStreamUnauthenticated(${stream.id}, this.checked)">
                            <span>Allow unauthenticated access (video visible on public /live page)</span>
                        </label>
                    </div>
                </div>

                <div class="info-section">
                    <h4>Standard RTMP (Plain)</h4>
                    <p class="info-description">Enable plain RTMP on port 1935 for encoders that don't support RTMPS. Uses temporary tokens instead of your permanent stream key for security.</p>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" ${stream.rtmp_enabled ? 'checked' : ''} onchange="toggleStreamRtmp(${stream.id}, this.checked)">
                            <span>Enable standard RTMP publishing</span>
                        </label>
                    </div>
                    ${stream.rtmp_enabled ? `
                    <div id="rtmp-token-section">
                        <div id="rtmp-token-result" style="display: none; margin-top: 0.75rem;"></div>
                    </div>
                    ` : ''}
                </div>

                ${stream.public_key ? `
                <div class="info-section">
                    <h4>Public API Key</h4>
                    <p class="info-description">Share this key with viewers for read-only access to your stream.</p>
                    <div class="form-group">
                        <label>Viewing Key (read-only)</label>
                        <div class="input-with-copy">
                            <input type="text" value="${stream.public_key}" readonly>
                            <button class="btn btn-sm btn-secondary" data-copy="public-key">Copy</button>
                        </div>
                        <small style="color: var(--text-muted);">Safe to share - viewers cannot modify your stream with this key.</small>
                    </div>
                </div>
                ` : ''}

                <div class="info-section">
                    <h4>Playback URLs</h4>
                    <div class="form-group">
                        <label>HLS (for web players)</label>
                        <div class="input-with-copy">
                            <input type="text" value="${hlsUrl}" readonly>
                            <button class="btn btn-sm btn-secondary" data-copy="hls-url">Copy</button>
                        </div>
                        <small style="color: var(--text-muted);">Proxied through Portal on port 443</small>
                    </div>
                </div>

                <div class="info-section">
                    <h4>Chat Moderators</h4>
                    <p class="info-description">Moderators you appoint can pin messages, time out and ban viewers, start polls and set slow mode in this stream's chat only. They cannot act on you, on each other or on administrators, and appointing someone does not let them watch a private stream. Up to 20.</p>
                    <div id="stream-mods-list"></div>
                    <div class="form-group" style="margin-top: 0.5rem;">
                        <label for="stream-mod-search">Appoint a member</label>
                        <input type="text" id="stream-mod-search" maxlength="40" placeholder="Search by name" autocomplete="off">
                        <div id="stream-mod-results"></div>
                    </div>
                </div>

                <div class="info-section">
                    <h4>Schedule</h4>
                    <p class="info-description">Plan when you go live. Members who may watch the stream see a countdown while it is offline and can mark themselves interested; each gets one reminder 10 minutes before the start.</p>
                    <div id="stream-schedule-mount"></div>
                </div>

                <div class="info-section">
                    <h4>Multi-Platform Relay</h4>
                    <p class="info-description">Relay your stream to external platforms (Twitch, YouTube, Kick, etc.) simultaneously.</p>
                    <div id="relay-destinations-list"></div>
                    <button class="btn btn-sm btn-primary" onclick="showAddRelayModal(${stream.id})" style="margin-top: 0.5rem;">Add Relay Destination</button>
                </div>

                <div class="form-actions">
                    <button class="btn btn-warning" onclick="regenerateStreamKey(${stream.id})">Regenerate Key</button>
                    <button class="btn btn-warning" onclick="regeneratePublicKey(${stream.id})">Rotate Share Link</button>
                    ${stream.rtmp_enabled ? `<button class="btn btn-primary" onclick="generateRtmpToken(${stream.id})">Generate RTMP Token</button>` : ''}
                    <button class="btn btn-secondary" onclick="closeModal('stream-details-modal')">Close</button>
                </div>
            </div>
        `;

        // Set as a property, not rendered into the markup: escapeHtml leaves double quotes alone,
        // so a message containing one would cut the attribute short
        document.getElementById('stream-golive-input').value = stream.golive_message || '';
        document.getElementById('stream-game-input').value = stream.game || '';
        loadGameSuggestions();
        const audienceSelect = document.getElementById('stream-golive-audience');
        audienceSelect.value = stream.golive_audience === 'everyone' ? 'everyone' : 'followers';
        audienceSelect.dataset.current = audienceSelect.value;      // restored if a save fails

        showModal('stream-details-modal');

        // Load relay destinations
        loadRelayDestinations(streamId);
        loadStreamMods(streamId);
        bindStreamModSearch(streamId);
        // "Use this title" renames the stream on the server: the name field, the heading and the grid follow, or
        // Save under the name field would put the old name back
        if (window.StreamSchedule) window.StreamSchedule.mountOwner(document.getElementById('stream-schedule-mount'), streamId, (name) => {
            if (!name) return;
            const nameInput = document.getElementById('stream-name-input');
            if (nameInput) nameInput.value = name;
            const heading = document.getElementById('stream-details-title');
            if (heading) heading.textContent = name;
            loadUserStreams();
        });

        // Bind copy buttons programmatically to avoid inlining secrets in onclick attributes
        const copyValues = {
            'rtmp-url': rtmpUrl,
            'stream-key': stream.stream_key,
            'public-key': stream.public_key || '',
            'hls-url': hlsUrl
        };
        document.querySelectorAll('#stream-details-content [data-copy]').forEach(btn => {
            const key = btn.getAttribute('data-copy');
            if (copyValues[key] !== undefined) {
                btn.addEventListener('click', () => copyToClipboard(copyValues[key]));
            }
        });

    } catch (error) {
        console.error('Failed to load stream details:', error);
        Portal.toast('Failed to load stream details', 'error');
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
 * Update stream name
 */
async function updateStreamName(streamId) {
    const input = document.getElementById('stream-name-input');
    const btn = document.getElementById('save-name-btn');
    const name = input.value.trim();
    if (!name) {
        Portal.toast('Stream name cannot be empty', 'error');
        return;
    }
    Portal.setButtonLoading(btn, true);
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });
        if (response.ok) {
            Portal.flashButtonSuccess(btn);
            document.getElementById('stream-details-title').textContent = name;
            Portal.toast('Stream name updated', 'success');
            loadUserStreams();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update name', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to update stream name', 'error');
    } finally {
        Portal.setButtonLoading(btn, false);
    }
}

/**
 * Fill a game field's suggestions (the settings form's, or the create window's with its own
 * list id): the games used before and those of public streams.
 * Option values are set as properties, never as markup.
 */
async function loadGameSuggestions(listId = 'stream-game-list') {
    const list = document.getElementById(listId);
    if (!list) return;
    try {
        const response = await Portal.fetch('/api/streams/games');
        if (!response.ok) return;
        const data = await response.json();
        list.replaceChildren();
        for (const game of (data.games || [])) {
            const option = document.createElement('option');
            option.value = game;
            list.appendChild(option);
        }
    } catch (error) {
        // suggestions are optional
    }
}

/**
 * Update the stream's game (empty clears it)
 */
async function updateStreamGame(streamId) {
    const input = document.getElementById('stream-game-input');
    const btn = document.getElementById('save-game-btn');
    const game = input.value.trim();
    Portal.setButtonLoading(btn, true);
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ game })
        });
        if (response.ok) {
            Portal.flashButtonSuccess(btn);
            Portal.toast('Game updated', 'success');
            loadUserStreams();
            loadGameSuggestions();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update game', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to update game', 'error');
    } finally {
        Portal.setButtonLoading(btn, false);
    }
}

/**
 * Update stream description
 */
async function updateStreamDescription(streamId) {
    const input = document.getElementById('stream-description-input');
    const btn = document.getElementById('save-description-btn');
    const description = input.value.trim();
    Portal.setButtonLoading(btn, true);
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ description })
        });
        if (response.ok) {
            Portal.flashButtonSuccess(btn);
            Portal.toast('Description updated', 'success');
            loadUserStreams();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update description', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to update description', 'error');
    } finally {
        Portal.setButtonLoading(btn, false);
    }
}

/**
 * Update the go-live message (empty: the default message)
 */
async function updateStreamGoLiveMessage(streamId) {
    const input = document.getElementById('stream-golive-input');
    const btn = document.getElementById('save-golive-btn');
    const golive_message = input.value.trim();
    Portal.setButtonLoading(btn, true);
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ golive_message })
        });
        if (response.ok) {
            Portal.flashButtonSuccess(btn);
            Portal.toast('Go-live message updated', 'success');
            loadUserStreams();
        } else {
            const data = await response.json();
            Portal.toast(data.error || 'Failed to update the go-live message', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to update the go-live message', 'error');
    } finally {
        Portal.setButtonLoading(btn, false);
    }
}

/**
 * Choose who a go-live is announced to: followers or everyone who can watch
 */
async function updateStreamGoLiveAudience(streamId, golive_audience) {
    // The select shows the new choice already: on a failure it goes back to the saved one
    const select = document.getElementById('stream-golive-audience');
    const previous = select ? select.dataset.current : null;
    const restore = () => { if (select && previous != null) select.value = previous; };
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ golive_audience })
        });
        if (response.ok) {
            if (select) select.dataset.current = golive_audience;
            Portal.toast('Go-live audience updated', 'success');
        } else {
            restore();
            const data = await response.json().catch(() => ({}));
            Portal.toast(data.error || 'Failed to update the go-live audience', 'error');
        }
    } catch (error) {
        restore();
        Portal.toast('Failed to update the go-live audience', 'error');
    }
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        Portal.toast('Copied! Clipboard will clear in 30s', 'success');
        setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000);
    } catch (error) {
        console.error('Failed to copy:', error);
        Portal.toast('Copy failed — please select and copy manually', 'error');
    }
}

/**
 * Toggle stream public/private
 */
async function toggleStreamPublic(streamId, isPublic) {
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_public: isPublic })
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to update stream', 'error');
        } else {
            const data = await response.json().catch(() => ({}));
            loadUserStreams();
            if (data.public_key) {
                // The server rotated the playback key; refresh the open details
                // modal so its displayed values and Copy buttons use the new key.
                Portal.toast('Stream is private; share link rotated', 'success');
                showStreamDetails(streamId);
            }
        }
    } catch (error) {
        console.error('Failed to update stream:', error);
        Portal.toast('Failed to update stream', 'error');
    }
}

async function toggleStreamUnauthenticated(streamId, allowed) {
    try {
        // Enabling unauthenticated access implies public
        const body = { allow_unauthenticated: allowed };
        if (allowed) body.is_public = true;

        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to update stream', 'error');
        } else {
            loadUserStreams();
        }
    } catch (error) {
        console.error('Failed to update stream:', error);
        Portal.toast('Failed to update stream', 'error');
    }
}

/**
 * Toggle RTMP plain publishing for a stream
 */
async function toggleStreamRtmp(streamId, enabled) {
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rtmp_enabled: enabled ? 1 : 0 })
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to update stream', 'error');
        }
        // Refresh the modal to show/hide token section
        showStreamDetails(streamId);
    } catch (error) {
        console.error('Failed to toggle RTMP:', error);
        Portal.toast('Failed to update stream', 'error');
    }
}

/**
 * Generate a temporary RTMP publish token
 */
let _rtmpCountdownInterval = null;
async function generateRtmpToken(streamId) {
    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}/rtmp-token`, {
            method: 'POST'
        });

        const resultEl = document.getElementById('rtmp-token-result');
        if (!resultEl) return;
        resultEl.style.display = 'block';
        resultEl.innerHTML = `
            <div class="form-group">
                <label>RTMP Server</label>
                <div class="input-with-copy">
                    <input type="text" value="${escapeHtml(data.rtmp_url)}" readonly>
                    <button class="btn btn-sm btn-secondary" data-copy="rtmp-token-url">Copy</button>
                </div>
            </div>
            <div class="form-group">
                <label>Temporary Stream Key (expires in ${Math.floor(data.expires_in / 60)} min)</label>
                <div class="input-with-copy">
                    <input type="text" value="${escapeHtml(data.token)}" readonly id="rtmp-token-input">
                    <button class="btn btn-sm btn-secondary" data-copy="rtmp-token-key">Copy</button>
                </div>
                <small class="warning-text">Token binds to your IP on first use. Reconnects allowed within ${Math.floor((data.grace_seconds || 300) / 60)} min of disconnect.</small>
            </div>
            <div id="rtmp-token-countdown" style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem;"></div>
        `;

        // Bind copy buttons programmatically to avoid inlining tokens in onclick attributes
        const rtmpCopyValues = { 'rtmp-token-url': data.rtmp_url, 'rtmp-token-key': data.token };
        resultEl.querySelectorAll('[data-copy]').forEach(btn => {
            const key = btn.getAttribute('data-copy');
            if (rtmpCopyValues[key]) {
                btn.addEventListener('click', () => copyToClipboard(rtmpCopyValues[key]));
            }
        });

        // Start countdown timer
        if (_rtmpCountdownInterval) clearInterval(_rtmpCountdownInterval);
        let remaining = data.expires_in;
        const updateCountdown = () => {
            const el = document.getElementById('rtmp-token-countdown');
            if (!el || remaining <= 0) {
                clearInterval(_rtmpCountdownInterval);
                if (el) el.textContent = 'Token expired — generate a new one';
                return;
            }
            const m = Math.floor(remaining / 60);
            const s = remaining % 60;
            el.textContent = `Expires in ${m}:${String(s).padStart(2, '0')}`;
            remaining--;
        };
        updateCountdown();
        _rtmpCountdownInterval = setInterval(updateCountdown, 1000);

    } catch (error) {
        console.error('Failed to generate RTMP token:', error);
        Portal.toast(error.message || 'Failed to generate RTMP token', 'error');
    }
}

/**
 * Upload stream thumbnail
 */
async function uploadThumbnail(streamId, input) {
    const file = input.files[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
        Portal.toast('Please select an image file', 'error');
        return;
    }

    // Validate file size (5MB)
    if (file.size > 5 * 1024 * 1024) {
        Portal.toast('Image must be less than 5MB', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('thumbnail', file);

    try {
        const response = await Portal.fetch(`/api/streams/${streamId}/thumbnail`, {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            // Refresh the modal to show new thumbnail
            showStreamDetails(streamId);
            loadUserStreams();
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to upload thumbnail', 'error');
        }
    } catch (error) {
        console.error('Failed to upload thumbnail:', error);
        Portal.toast('Failed to upload thumbnail', 'error');
    }

    // Clear the input
    input.value = '';
}

/**
 * Delete stream thumbnail
 */
async function deleteThumbnail(streamId) {
    if (!confirm('Remove the thumbnail?')) return;

    try {
        const response = await Portal.fetch(`/api/streams/${streamId}/thumbnail`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showStreamDetails(streamId);
            loadUserStreams();
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to remove thumbnail', 'error');
        }
    } catch (error) {
        console.error('Failed to remove thumbnail:', error);
        Portal.toast('Failed to remove thumbnail', 'error');
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
        const response = await Portal.fetch(`/api/streams/${streamId}/regenerate-key`, {
            method: 'POST'
        });

        if (response.ok) {
            showStreamDetails(streamId);
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to regenerate key', 'error');
        }
    } catch (error) {
        console.error('Failed to regenerate key:', error);
        Portal.toast('Failed to regenerate key', 'error');
    }
}

/**
 * Rotate the share link (playback key). Old viewing URLs stop working.
 */
async function regeneratePublicKey(streamId) {
    if (!confirm('Rotate the share link? Existing viewing links, embeds and open watch pages for this stream will stop working.')) {
        return;
    }

    try {
        const response = await Portal.fetch(`/api/streams/${streamId}/regenerate-public-key`, {
            method: 'POST'
        });

        if (response.ok) {
            Portal.toast('Share link rotated', 'success');
            showStreamDetails(streamId);
            loadUserStreams();
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to rotate share link', 'error');
        }
    } catch (error) {
        console.error('Failed to rotate share link:', error);
        Portal.toast('Failed to rotate share link', 'error');
    }
}

/**
 * Delete stream
 */
async function deleteStream(streamId) {
    if (!confirm('Are you sure you want to delete this stream?')) {
        return;
    }

    try {
        const response = await Portal.fetch(`/api/streams/${streamId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadUserStreams();
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to delete stream', 'error');
        }
    } catch (error) {
        console.error('Failed to delete stream:', error);
        Portal.toast('Failed to delete stream', 'error');
    }
}

/**
 * View a community stream - redirects to streams page
 */
function viewStream(publicKey) {
    if (publicKey) {
        window.location.href = `/streams#watch-${publicKey}`;
    }
}

/**
 * Open stream in a new window
 */
function viewStreamNewWindow(publicKey, event) {
    if (event) {
        event.stopPropagation();
    }
    if (publicKey) {
        window.open(`/watch/${publicKey}`, '_blank', 'width=1280,height=720');
    }
}

/**
 * Connect to stream chat using stream key authentication
 */
function connectStreamChat(streamKey) {
    if (streamChatWs) {
        streamChatWs.close();
    }

    const wsUrl = Portal.getWebSocketUrl('/ws/chat');
    streamChatWs = new WebSocket(wsUrl);

    streamChatWs.onopen = () => {
        // Use stream key for authentication (same as video playback)
        streamChatWs.send(JSON.stringify({
            type: 'join',
            stream_key: streamKey
        }));
    };

    streamChatWs.onmessage = (event) => {
        let data;
        try { data = JSON.parse(event.data); } catch { return; }
        if (data.type === 'message') {
            appendStreamChatMessage(data);
        } else if (data.type === 'history') {
            document.getElementById('stream-chat-messages').innerHTML = '';
            data.messages.forEach(msg => appendStreamChatMessage(msg));
        } else if (data.type === 'message_deleted') {
            const msgId = String(data.message_id).replace(/[^a-zA-Z0-9_-]/g, '');
            const el = document.querySelector(`#stream-chat-messages .chat-message[data-message-id="${msgId}"]`);
            if (el) el.remove();
        } else if (data.type === 'messages_pruned') {
            removeStreamChatMessages(data.ids);
        }
    };

    streamChatWs.onclose = () => {
        streamChatWs = null;
    };
}

/**
 * Remove the messages a prune took out of the stream chat (the ids of one messages_pruned frame).
 * Ids that are not on screen, and anything that is not a list, are ignored.
 */
function removeStreamChatMessages(ids) {
    if (!Array.isArray(ids)) return;
    const wanted = new Set(ids.map(id => String(id).replace(/[^a-zA-Z0-9_-]/g, '')));
    document.querySelectorAll('#stream-chat-messages .chat-message').forEach(el => {
        if (wanted.has(el.dataset.messageId)) el.remove();
    });
}

/**
 * Append a chat message to the stream chat
 */
function appendStreamChatMessage(msg) {
    const messagesEl = document.getElementById('stream-chat-messages');
    const messageEl = document.createElement('div');
    messageEl.className = 'chat-message';
    if (msg.id) messageEl.dataset.messageId = msg.id;
    const displayName = msg.nickname || msg.username;
    const avatar = msg.avatar || {};
    const avatarColor = msg.anonymous ? '#6b7280' : (avatar.color || '#3b82f6');
    const avatarContent = msg.anonymous ? '?' : (avatar.emoji || (displayName || '?')[0].toUpperCase());

    // Reply preview
    let replyHtml = '';
    if (msg.reply_preview) {
        replyHtml = `<div style="font-size:0.7rem;color:var(--text-muted);border-left:2px solid rgba(255,255,255,0.2);padding-left:0.4rem;margin-bottom:0.15rem;"><strong>${escapeHtml(msg.reply_preview.username)}</strong>: ${escapeHtml(msg.reply_preview.message)}</div>`;
    }

    // Image
    const imageHtml = msg.image_url
        ? `<br><img src="${escapeHtml(msg.image_url)}" alt="image" style="max-width:180px;max-height:120px;border-radius:4px;margin-top:0.2rem;cursor:pointer;" data-fullimg="${escapeHtml(msg.image_url)}" loading="lazy">`
        : '';

    messageEl.innerHTML = `
        <div style="display: flex; gap: 0.5rem; align-items: flex-start;">
            <div style="width: 24px; height: 24px; border-radius: 50%; background: ${escapeHtml(avatarColor)}; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; flex-shrink: 0;">${escapeHtml(avatarContent)}</div>
            <div style="min-width: 0;">
                ${replyHtml}
                <span class="chat-username">${escapeHtml(displayName)}</span>
                <span class="chat-text">${escapeHtml(msg.message || '')}${imageHtml}</span>
            </div>
        </div>
    `;
    const img = messageEl.querySelector('img[data-fullimg]');
    if (img) img.addEventListener('click', () => window.open(img.dataset.fullimg, '_blank'));
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
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// =========================================================================
// Multi-Platform Relay
// =========================================================================

const RELAY_PLATFORMS = {
    twitch: { name: 'Twitch', color: '#9146ff' },
    youtube: { name: 'YouTube', color: '#ff0000' },
    kick: { name: 'Kick', color: '#53fc18' },
    portal: { name: 'Open Relay Portal', color: '#3b82f6' },
    custom: { name: 'Custom', color: '#6b7280' },
};

/**
 * Chat moderators of a stream: list, remove, search and appoint. Built from text nodes;
 * the ids stay in closures, never in attributes.
 */
async function loadStreamMods(streamId) {
    const listEl = document.getElementById('stream-mods-list');
    if (!listEl) return;
    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}/mods`);
        const mods = data.mods || [];
        listEl.replaceChildren();
        if (!mods.length) {
            const none = document.createElement('p');
            none.className = 'info-description';
            none.textContent = 'No moderators yet.';
            listEl.appendChild(none);
            return;
        }
        mods.forEach(m => {
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:0.5rem;padding:0.3rem 0;';
            const name = document.createElement('span');
            name.textContent = m.nickname || m.username;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-sm btn-secondary';
            btn.textContent = 'Remove';
            btn.addEventListener('click', async () => {
                const r = await Portal.fetch(`/api/streams/${streamId}/mods/${Number(m.user_id)}`, { method: 'DELETE' });
                if (r.ok) { Portal.toast('Moderator removed', 'success'); loadStreamMods(streamId); }
                else { Portal.toast('Could not remove the moderator', 'error'); }
            });
            row.append(name, btn);
            listEl.appendChild(row);
        });
    } catch (error) {
        listEl.textContent = 'Could not load the moderators.';
    }
}

function bindStreamModSearch(streamId) {
    const input = document.getElementById('stream-mod-search');
    const results = document.getElementById('stream-mod-results');
    if (!input || !results) return;
    let timer = null;
    input.addEventListener('input', () => {
        clearTimeout(timer);
        const q = input.value.trim();
        if (q.length < 2) { results.replaceChildren(); return; }
        timer = setTimeout(async () => {
            try {
                const data = await Portal.fetchJSON('/api/chat/users?q=' + encodeURIComponent(q));
                results.replaceChildren();
                (data.users || []).forEach(u => {
                    const row = document.createElement('div');
                    row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:0.5rem;padding:0.2rem 0;';
                    const name = document.createElement('span');
                    name.textContent = u.nickname || u.username;
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = 'btn btn-sm btn-primary';
                    btn.textContent = 'Appoint';
                    btn.addEventListener('click', async () => {
                        const r = await Portal.fetch(`/api/streams/${streamId}/mods`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ user_id: u.id })
                        });
                        if (r.ok) {
                            Portal.toast('Moderator appointed', 'success');
                            results.replaceChildren();
                            input.value = '';
                            loadStreamMods(streamId);
                        } else {
                            const d = await r.json().catch(() => ({}));
                            Portal.toast(d.error || 'Could not appoint the moderator', 'error');
                        }
                    });
                    row.append(name, btn);
                    results.appendChild(row);
                });
            } catch (error) {
                results.textContent = 'Search failed.';
            }
        }, 250);
    });
}

async function loadRelayDestinations(streamId) {
    const listEl = document.getElementById('relay-destinations-list');
    if (!listEl) return;

    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}/relays`);
        const relays = data.relays || [];

        if (relays.length === 0) {
            listEl.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem;">No relay destinations configured.</p>';
            return;
        }

        listEl.innerHTML = relays.map(relay => {
            const platform = RELAY_PLATFORMS[relay.platform] || RELAY_PLATFORMS.custom;
            const hasError = !!relay.last_error;
            return `
                <div class="relay-destination-row" data-relay-id="${relay.id}">
                    <span class="relay-platform-badge" style="background: ${platform.color};">${escapeHtml(platform.name)}</span>
                    <span class="relay-name">${escapeHtml(relay.name)}</span>
                    <span class="relay-url" title="${escapeHtml(relay.rtmp_url)}">${escapeHtml(relay.rtmp_url)}</span>
                    <div class="relay-actions">
                        <label class="relay-toggle" title="${relay.enabled ? 'Enabled' : 'Disabled'}">
                            <input type="checkbox" ${relay.enabled ? 'checked' : ''} data-relay-toggle="${relay.id}" data-stream-id="${streamId}">
                            <span class="relay-toggle-slider"></span>
                        </label>
                        ${hasError ? `<button class="btn btn-sm btn-warning" data-relay-logs="${relay.id}" data-stream-id="${streamId}" title="View last error">Last Error</button>` : ''}
                        <button class="btn btn-sm btn-secondary" data-relay-edit="${relay.id}" data-stream-id="${streamId}">Edit</button>
                        <button class="btn btn-sm btn-danger" data-relay-delete="${relay.id}" data-stream-id="${streamId}">Delete</button>
                    </div>
                </div>
            `;
        }).join('');

        // Bind events via data attributes
        listEl.querySelectorAll('[data-relay-toggle]').forEach(input => {
            input.addEventListener('change', () => {
                toggleRelayEnabled(
                    parseInt(input.dataset.streamId),
                    parseInt(input.dataset.relayToggle),
                    input.checked
                );
            });
        });
        listEl.querySelectorAll('[data-relay-logs]').forEach(btn => {
            btn.addEventListener('click', () => {
                viewRelayError(
                    parseInt(btn.dataset.streamId),
                    parseInt(btn.dataset.relayLogs)
                );
            });
        });
        listEl.querySelectorAll('[data-relay-edit]').forEach(btn => {
            btn.addEventListener('click', () => {
                showEditRelayModal(
                    parseInt(btn.dataset.streamId),
                    parseInt(btn.dataset.relayEdit)
                );
            });
        });
        listEl.querySelectorAll('[data-relay-delete]').forEach(btn => {
            btn.addEventListener('click', () => {
                deleteRelay(
                    parseInt(btn.dataset.streamId),
                    parseInt(btn.dataset.relayDelete)
                );
            });
        });

    } catch (error) {
        console.error('Failed to load relay destinations:', error);
        listEl.innerHTML = '<p style="color: var(--danger);">Failed to load relay destinations.</p>';
    }
}

async function viewRelayError(streamId, relayId) {
    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}/relays/${relayId}/logs`);
        const error = data.last_error || 'No error details available.';
        const when = data.last_error_at ? new Date(data.last_error_at).toLocaleString() : '';

        const titleEl = document.getElementById('confirm-title');
        const msgEl = document.getElementById('confirm-message');
        const confirmBtn = document.getElementById('confirm-btn');
        const cancelBtn = document.querySelector('#confirm-modal .btn-secondary');
        if (!titleEl || !msgEl) return;

        // Save original state
        const origTitle = titleEl.textContent;
        const origMsg = msgEl.innerHTML;
        const origConfirmDisplay = confirmBtn ? confirmBtn.style.display : '';
        const origCancelText = cancelBtn ? cancelBtn.textContent : '';

        titleEl.textContent = 'Relay Error Log';
        msgEl.innerHTML = (when ? `<small style="color:var(--text-muted)">Last failure: ${escapeHtml(when)}</small><br>` : '') +
            `<pre style="white-space:pre-wrap;word-break:break-all;margin-top:0.5rem;font-size:0.8rem;max-height:300px;overflow-y:auto;background:var(--bg-secondary);padding:0.75rem;border-radius:4px;">${escapeHtml(error)}</pre>`;
        if (confirmBtn) confirmBtn.style.display = 'none';
        if (cancelBtn) cancelBtn.textContent = 'Close';

        // Set pending action to null so the confirm button (if shown) just closes
        pendingConfirmAction = null;

        showModal('confirm-modal');

        // Restore modal state on close (one-shot, covers ×, Cancel, and backdrop)
        function restoreConfirmModal() {
            titleEl.textContent = origTitle;
            msgEl.innerHTML = origMsg;
            if (confirmBtn) confirmBtn.style.display = origConfirmDisplay;
            if (cancelBtn) cancelBtn.textContent = origCancelText;
        }
        document.querySelectorAll('#confirm-modal [onclick*="closeModal"], #confirm-modal .modal-backdrop').forEach(el => {
            el.addEventListener('click', restoreConfirmModal, { once: true });
        });
    } catch (err) {
        Portal.toast('Failed to load relay error log', 'error');
    }
}

async function showAddRelayModal(streamId) {
    const modal = document.getElementById('relay-destination-modal');
    if (!modal) return;

    document.getElementById('relay-modal-title').textContent = 'Add Relay Destination';
    document.getElementById('relay-form').reset();
    document.getElementById('relay-stream-id').value = streamId;
    document.getElementById('relay-id').value = '';
    document.getElementById('relay-stream-key').required = true;

    // Pre-fill default URL on platform change
    onRelayPlatformChange();

    showModal('relay-destination-modal');
}

async function showEditRelayModal(streamId, relayId) {
    const modal = document.getElementById('relay-destination-modal');
    if (!modal) return;

    document.getElementById('relay-modal-title').textContent = 'Edit Relay Destination';
    document.getElementById('relay-stream-id').value = streamId;
    document.getElementById('relay-id').value = relayId;
    document.getElementById('relay-stream-key').required = false;
    document.getElementById('relay-stream-key').placeholder = 'Leave blank to keep existing';

    // Load current relay data via the list (keys are redacted)
    try {
        const data = await Portal.fetchJSON(`/api/streams/${streamId}/relays`);
        const relay = (data.relays || []).find(r => r.id === relayId);
        if (!relay) {
            Portal.toast('Relay not found', 'error');
            return;
        }
        document.getElementById('relay-platform').value = relay.platform;
        document.getElementById('relay-name').value = relay.name;
        document.getElementById('relay-rtmp-url').value = relay.rtmp_url;
        document.getElementById('relay-stream-key').value = '';
    } catch (error) {
        Portal.toast('Failed to load relay', 'error');
        return;
    }

    showModal('relay-destination-modal');
}

let _relayPlatformDefaults = null;

async function onRelayPlatformChange() {
    const platform = document.getElementById('relay-platform').value;
    const urlInput = document.getElementById('relay-rtmp-url');

    // Fetch platform defaults from server on first use
    if (!_relayPlatformDefaults) {
        try {
            const data = await Portal.fetchJSON('/api/relay-platforms');
            _relayPlatformDefaults = data.platforms || {};
        } catch { _relayPlatformDefaults = {}; }
    }

    const currentUrl = urlInput.value.trim();
    const allDefaults = Object.values(_relayPlatformDefaults).map(p => p.default_url).filter(Boolean);
    const isDefault = !currentUrl || allDefaults.includes(currentUrl);
    const platformDefault = (_relayPlatformDefaults[platform] || {}).default_url || '';
    if (isDefault) {
        urlInput.value = platformDefault;
    }
}

async function submitRelayDestination(event) {
    event.preventDefault();
    const streamId = parseInt(document.getElementById('relay-stream-id').value);
    const relayId = document.getElementById('relay-id').value;
    const submitBtn = event.target.querySelector('button[type="submit"]');

    const body = {
        platform: document.getElementById('relay-platform').value,
        name: document.getElementById('relay-name').value.trim(),
        rtmp_url: document.getElementById('relay-rtmp-url').value.trim(),
    };

    const streamKey = document.getElementById('relay-stream-key').value.trim();
    if (streamKey) {
        body.stream_key = streamKey;
    }

    const isEdit = !!relayId;
    const url = isEdit
        ? `/api/streams/${streamId}/relays/${relayId}`
        : `/api/streams/${streamId}/relays`;
    const method = isEdit ? 'PUT' : 'POST';

    Portal.setButtonLoading(submitBtn, true);
    try {
        const response = await Portal.fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            Portal.flashButtonSuccess(submitBtn);
            Portal.toast(isEdit ? 'Relay updated' : 'Relay added', 'success');
            setTimeout(() => closeModal('relay-destination-modal'), 600);
            loadRelayDestinations(streamId);
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to save relay', 'error');
        }
    } catch (error) {
        console.error('Relay save error:', error);
        Portal.toast('Failed to save relay', 'error');
    } finally {
        Portal.setButtonLoading(submitBtn, false);
    }
}

async function toggleRelayEnabled(streamId, relayId, enabled) {
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}/relays/${relayId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to update relay', 'error');
            loadRelayDestinations(streamId);
        }
    } catch (error) {
        Portal.toast('Failed to update relay', 'error');
        loadRelayDestinations(streamId);
    }
}

async function deleteRelay(streamId, relayId) {
    if (!confirm('Delete this relay destination?')) return;
    try {
        const response = await Portal.fetch(`/api/streams/${streamId}/relays/${relayId}`, {
            method: 'DELETE'
        });
        if (response.ok) {
            Portal.toast('Relay deleted', 'success');
            loadRelayDestinations(streamId);
        } else {
            const error = await response.json().catch(() => ({}));
            Portal.toast(error.error || 'Failed to delete relay', 'error');
        }
    } catch (error) {
        Portal.toast('Failed to delete relay', 'error');
    }
}

// Auto-refresh interval for community streams (30 seconds)
let communityStreamsRefreshInterval = null;

/**
 * Start auto-refreshing community streams
 */
function startCommunityStreamsRefresh() {
    if (communityStreamsRefreshInterval) return;

    communityStreamsRefreshInterval = setInterval(() => {
        // Only refresh if the community-streams tab is visible
        const tab = document.querySelector('[data-tab="community-streams"]');
        if (tab && tab.classList.contains('active')) {
            loadCommunityStreams();
        }
    }, 30000); // Refresh every 30 seconds
}

/**
 * Stop auto-refreshing community streams
 */
function stopCommunityStreamsRefresh() {
    if (communityStreamsRefreshInterval) {
        clearInterval(communityStreamsRefreshInterval);
        communityStreamsRefreshInterval = null;
    }
}

// Load streams when tab is switched
const originalSwitchTab = window.switchTab;
window.switchTab = function(tab) {
    if (typeof originalSwitchTab === 'function') {
        originalSwitchTab(tab);
    }

    if (tab === 'my-streams') {
        loadUserStreams();
        stopCommunityStreamsRefresh();
    } else if (tab === 'community-streams') {
        loadCommunityStreams();
        startCommunityStreamsRefresh();
    } else {
        stopCommunityStreamsRefresh();
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
        const el = document.getElementById(modalId);
        if (el) el.style.display = 'none';
    }
};
