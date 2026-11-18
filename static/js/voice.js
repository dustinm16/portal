/**
 * Voice Chat Module — WebRTC P2P mesh voice chat
 * Piggybacks signaling on existing /ws/chat WebSocket.
 * Supports VAD (Voice Activity Detection) and PTT (Push-to-Talk).
 * Per-user playback volume (0-200%) and local mute, kept in this browser only.
 */
const VoiceChat = (() => {
    // State
    let _ws = null;
    let _myUserId = null;         // Our own user_id (to skip self-peering)
    let _inVoice = false;
    let _muted = false;
    let _deafened = false;
    let _localStream = null;
    let _audioContext = null;
    let _analyser = null;
    let _vadInterval = null;
    let _speaking = false;
    let _iceServers = [];
    let _peers = new Map();       // user_id -> RTCPeerConnection
    // Remote audio per peer: {el, stream, track, source, gain}. Every change of
    // loudness goes through _applyGain.
    let _playback = new Map();    // user_id -> playback entry
    let _playCtx = null;          // shared playback AudioContext (not the VAD one)
    let _playCtxFailed = false;   // creating it threw: element volume only
    let _peerPrefs = new Map();   // user_id -> {vol, muted}, this browser only
    let _peerPrefsKey = null;
    let _volumeIgnored = false;   // the element did not take a volume below 100%
    let _menu = null;             // the open per-user popover
    let _voiceUsers = new Map();  // user_id -> {username, muted, deafened, speaking}
    let _onStateChange = null;    // callback for UI updates
    let _onScreenShareChange = null; // callback for screen share UI
    let _prefs = { mode: 'vad', pttKey: 'Space', vadThreshold: -50, noiseGate: true };
    let _pttActive = false;
    let _pendingCandidates = new Map(); // user_id -> [candidates] (buffered before remote desc set)
    let _makingOffer = new Set();  // user_ids we're currently creating offers for

    // Reconnect state. The resume token is returned by the server when we join
    // and lives only in this variable (never in storage), so another tab of the
    // same account cannot take the call over. _reconnecting is true while our
    // own chat socket is down and we are waiting to resume on a new one.
    const GIVE_UP_MS = 30000;       // server keeps the seat for 20 s
    let _room = null;
    let _resumeToken = null;
    let _reconnecting = false;
    let _giveUpTimer = null;
    // A Leave clicked while the socket was down: the seat is still held on the
    // server, so the next socket sends a leave with the resume token.
    let _pendingLeave = null;       // {room, token}

    // Screen sharing state
    let _screenStream = null;       // MediaStream from getDisplayMedia
    let _screenSharing = false;     // Are we sharing?
    let _screenSharerId = null;     // Who is sharing (user_id or null)
    let _screenSenders = new Map(); // user_id -> [RTCRtpSender] for screen tracks

    function _loadPrefs() {
        try {
            const saved = localStorage.getItem('voice_prefs');
            if (saved) Object.assign(_prefs, JSON.parse(saved));
        } catch {}
    }

    function _savePrefs() {
        try {
            localStorage.setItem('voice_prefs', JSON.stringify(_prefs));
        } catch {}
    }

    async function _fetchIceServers() {
        try {
            const resp = await fetch('/api/voice/ice-servers', { credentials: 'include' });
            if (resp.ok) {
                const data = await resp.json();
                _iceServers = data.ice_servers || [];
            }
        } catch (e) {
            console.warn('[Voice] Failed to fetch ICE servers:', e);
        }
    }

    function init(ws, onStateChange, onScreenShareChange, myUserId) {
        _ws = ws;
        _myUserId = myUserId != null ? Number(myUserId) : null;
        _onStateChange = onStateChange || null;
        _onScreenShareChange = onScreenShareChange || null;
        _loadPrefs();
        _loadPeerPrefs();
        _fetchIceServers();
        if (ws && !ws.__voiceBound) {
            ws.__voiceBound = true;
            ws.addEventListener('close', (ev) => _onSocketClosed(ws, ev));
        }
        // A Leave clicked while disconnected: end the held seat on this socket.
        if (_pendingLeave && !_inVoice) {
            setTimeout(() => _sendPendingLeave(ws), 0);
        }
        // A new socket while we are in a call: take our seat back on it.
        if (_inVoice) {
            if (!_resumeToken || !_room) {
                _cleanup();
                _notifyState();
            } else {
                // After the page's own channel join, which it sends right after init().
                setTimeout(() => _sendResume(ws), 0);
            }
        }
    }

    function _sendResume(ws) {
        if (!_inVoice || ws !== _ws || ws.readyState !== WebSocket.OPEN) return;
        ws.send(JSON.stringify({
            type: 'voice_join', resume: true, room: _room, resume_token: _resumeToken
        }));
    }

    function _sendPendingLeave(ws) {
        if (!_pendingLeave || _inVoice || ws !== _ws || ws.readyState !== WebSocket.OPEN) return;
        const p = _pendingLeave;
        _pendingLeave = null;
        ws.send(JSON.stringify({ type: 'voice_leave', room: p.room, resume_token: p.token }));
    }

    function _clearGiveUp() {
        if (_giveUpTimer) { clearTimeout(_giveUpTimer); _giveUpTimer = null; }
    }

    function _onSocketClosed(ws, ev) {
        if (ws !== _ws || !_inVoice) return;
        if (ev && ev.code === 4001) {
            // Signed out elsewhere: the server ended the call, the page leaves.
            _pendingLeave = null;
            _cleanup();
            _notifyState();
            return;
        }
        // Keep the microphone and the peer connections: audio between browsers
        // does not go through this socket and often keeps flowing.
        _reconnecting = true;
        _clearGiveUp();
        _giveUpTimer = setTimeout(() => {
            _giveUpTimer = null;
            if (_inVoice && _reconnecting) _lostForGood();
        }, GIVE_UP_MS);
        _notifyState();
    }

    function _lostForGood() {
        _pendingLeave = null;
        _cleanup();
        _notifyState();
        if (window.Portal && Portal.toast) Portal.toast('Voice connection lost. Join voice again.', 'error');
    }

    function handleMessage(data) {
        const type = data.type;
        if (type === 'voice_state') {
            _handleVoiceState(data);
        } else if (type === 'voice_denied') {
            // The server refused or ended this user's voice session
            if (_inVoice) { _cleanup(); _notifyState(); }
            if (window.Portal && Portal.toast && data.message) Portal.toast(data.message, 'error');
        } else if (type === 'voice_resume_failed') {
            // The seat was gone (grace over, or not ours to take back)
            if (_inVoice) { _cleanup(); _notifyState(); }
            if (window.Portal && Portal.toast) Portal.toast(data.message || 'Voice connection lost. Join voice again.', 'error');
        } else if (type === 'voice_user_reconnecting') {
            _setUserReconnecting(data.user_id, true);
        } else if (type === 'voice_user_resumed') {
            _setUserReconnecting(data.user_id, false);
        } else if (type === 'voice_user_joined') {
            _handleUserJoined(data);
        } else if (type === 'voice_user_left') {
            _handleUserLeft(data);
        } else if (type === 'voice_signal') {
            _handleSignal(data);
        } else if (type === 'voice_mute_changed') {
            _handleMuteChanged(data);
        } else if (type === 'voice_deafen_changed') {
            _handleDeafenChanged(data);
        } else if (type === 'voice_speaking_changed') {
            _handleSpeakingChanged(data);
        } else if (type === 'screen_share_started') {
            _handleScreenShareStarted(data);
        } else if (type === 'screen_share_stopped') {
            _handleScreenShareStopped(data);
        }
    }

    async function join(room) {
        if (_inVoice) return;
        // Created here, inside the click that started the join: a context made
        // after the microphone prompt may no longer count as a user gesture.
        _ensurePlayCtx();
        try {
            _localStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            });
        } catch (e) {
            console.error('[Voice] Microphone access denied:', e);
            _closePlayCtx();
            _notifyState();
            return;
        }

        // Send join to server (with optional room for DM voice)
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            const msg = { type: 'voice_join' };
            if (room) msg.room = room;
            _ws.send(JSON.stringify(msg));
        }
        _inVoice = true;
        _reconnecting = false;
        _muted = false;
        _deafened = false;
        _speaking = false;

        // Set up VAD or PTT
        _setupVoiceMode();
        _notifyState();
    }

    function leave() {
        if (!_inVoice) return;
        // Send leave to server
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'voice_leave' }));
        } else if (_reconnecting && _room && _resumeToken) {
            // The server still holds our seat; it is ended on the next socket.
            _pendingLeave = { room: _room, token: _resumeToken };
        }
        _cleanup();
        _notifyState();
    }

    function _cleanup() {
        _inVoice = false;
        _reconnecting = false;
        _room = null;
        _resumeToken = null;
        _clearGiveUp();
        _speaking = false;
        _pttActive = false;

        // Stop screen sharing
        if (_screenStream) {
            _screenStream.getTracks().forEach(t => t.stop());
            _screenStream = null;
        }
        _screenSharing = false;
        _screenSharerId = null;
        _screenSenders.clear();

        // Stop VAD
        if (_vadInterval) { clearInterval(_vadInterval); _vadInterval = null; }

        // Close all peer connections
        for (const [uid, pc] of _peers) {
            pc.close();
        }
        _peers.clear();

        // Remove audio elements, gain nodes and the playback context
        for (const uid of Array.from(_playback.keys())) _detachPlayback(uid);
        _closePlayCtx();
        _closeUserMenu();
        _pendingCandidates.clear();
        _makingOffer.clear();

        // Stop local stream
        if (_localStream) {
            _localStream.getTracks().forEach(t => t.stop());
            _localStream = null;
        }

        // Teardown audio context
        if (_audioContext) {
            _audioContext.close().catch(() => {});
            _audioContext = null;
            _analyser = null;
        }

        // Remove PTT listeners
        document.removeEventListener('keydown', _pttKeyDown);
        document.removeEventListener('keyup', _pttKeyUp);

        _voiceUsers.clear();
    }

    function toggleMute() {
        if (!_inVoice) return;
        _muted = !_muted;
        // Mute local track
        if (_localStream) {
            _localStream.getAudioTracks().forEach(t => { t.enabled = !_muted; });
        }
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'voice_mute', muted: _muted }));
        }
        _notifyState();
    }

    function toggleDeafen() {
        if (!_inVoice) return;
        _deafened = !_deafened;
        // Deafen silences every peer through the same path as a local mute
        _applyAllGains();
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'voice_deafen', deafened: _deafened }));
        }
        _notifyState();
    }

    function setMode(mode) {
        _prefs.mode = mode;
        _savePrefs();
        if (_inVoice) _setupVoiceMode();
        _notifyState();
    }

    function setPttKey(key) {
        _prefs.pttKey = key;
        _savePrefs();
    }

    function setVadThreshold(threshold) {
        _prefs.vadThreshold = threshold;
        _savePrefs();
    }

    // Voice mode setup
    function _setupVoiceMode() {
        // Clear existing
        if (_vadInterval) { clearInterval(_vadInterval); _vadInterval = null; }
        document.removeEventListener('keydown', _pttKeyDown);
        document.removeEventListener('keyup', _pttKeyUp);

        if (_prefs.mode === 'ptt') {
            // PTT: mute by default, unmute while key held
            if (_localStream) {
                _localStream.getAudioTracks().forEach(t => { t.enabled = false; });
            }
            document.addEventListener('keydown', _pttKeyDown);
            document.addEventListener('keyup', _pttKeyUp);
        } else {
            // VAD: set up audio analysis
            if (_localStream) {
                _localStream.getAudioTracks().forEach(t => { t.enabled = !_muted; });
            }
            _setupVAD();
        }
    }

    // PTT handlers
    function _pttKeyDown(e) {
        if (!_inVoice || _muted) return;
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
        if (e.code === _prefs.pttKey && !_pttActive) {
            _pttActive = true;
            if (_localStream) {
                _localStream.getAudioTracks().forEach(t => { t.enabled = true; });
            }
            _setSpeaking(true);
        }
    }

    function _pttKeyUp(e) {
        if (!_inVoice) return;
        if (e.code === _prefs.pttKey && _pttActive) {
            _pttActive = false;
            if (_localStream) {
                _localStream.getAudioTracks().forEach(t => { t.enabled = false; });
            }
            _setSpeaking(false);
        }
    }

    // VAD setup
    function _setupVAD() {
        if (!_localStream) return;
        try {
            _audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const source = _audioContext.createMediaStreamSource(_localStream);
            _analyser = _audioContext.createAnalyser();
            _analyser.fftSize = 2048;
            source.connect(_analyser);
        } catch (e) {
            console.warn('[Voice] VAD setup failed:', e);
            return;
        }

        const dataArray = new Float32Array(_analyser.fftSize);
        let silenceFrames = 0;
        const SILENCE_DELAY = 15; // ~750ms at 50ms interval

        _vadInterval = setInterval(() => {
            if (!_analyser || _muted) return;
            _analyser.getFloatTimeDomainData(dataArray);

            // Calculate RMS
            let sum = 0;
            for (let i = 0; i < dataArray.length; i++) {
                sum += dataArray[i] * dataArray[i];
            }
            const rms = Math.sqrt(sum / dataArray.length);
            const dBFS = rms > 0 ? 20 * Math.log10(rms) : -100;

            if (dBFS > _prefs.vadThreshold) {
                silenceFrames = 0;
                if (!_speaking) _setSpeaking(true);
            } else {
                silenceFrames++;
                if (silenceFrames >= SILENCE_DELAY && _speaking) {
                    _setSpeaking(false);
                }
            }
        }, 50);
    }

    function _setSpeaking(speaking) {
        if (_speaking === speaking) return;
        _speaking = speaking;
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'voice_speaking', speaking }));
        }
        _notifyState();
    }

    // ---- Per-user playback: volume 0-200%, local mute ---------------------
    // Remote audio plays through one shared AudioContext: stream -> GainNode ->
    // output. The <audio> element stays attached but muted, because Chromium
    // delivers no audio from a remote WebRTC stream to Web Audio unless the
    // stream is also attached to a media element. Where Web Audio is not used
    // (iOS, no AudioContext, a context that is not running) the element itself
    // plays, with its volume capped at 100%. Preferences are kept in this
    // browser's localStorage only and are never sent to the server.
    const MAX_VOLUME = 200;
    const MAX_VOLUME_ELEMENT = 100;
    const MAX_STORED_PEERS = 500;

    function _isIOS() {
        try {
            const ua = navigator.userAgent || '';
            if (/iPad|iPhone|iPod/.test(ua)) return true;
            // iPadOS reports itself as a Mac with a touch screen
            return navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1;
        } catch { return false; }
    }

    function _audioContextClass() {
        if (typeof window === 'undefined') return null;
        return window.AudioContext || window.webkitAudioContext || null;
    }

    function _webAudioWanted() {
        return !_playCtxFailed && !_isIOS() && !!_audioContextClass();
    }

    // Slider ceiling on this device
    function getMaxVolume() {
        return _webAudioWanted() ? MAX_VOLUME : MAX_VOLUME_ELEMENT;
    }

    function _ensurePlayCtx() {
        if (!_webAudioWanted()) return null;
        if (_playCtx && _playCtx.state === 'closed') _playCtx = null;
        if (!_playCtx) {
            try {
                const Ctor = _audioContextClass();
                _playCtx = new Ctor();
                _playCtx.onstatechange = () => _applyAllGains();
            } catch (e) {
                console.warn('[Voice] Web Audio playback unavailable:', e);
                _playCtx = null;
                _playCtxFailed = true;
                return null;
            }
        }
        if (_playCtx.state === 'suspended') {
            try {
                const p = _playCtx.resume();
                if (p && p.catch) p.catch(() => {});
            } catch {}
        }
        return _playCtx;
    }

    function _closePlayCtx() {
        if (!_playCtx) return;
        const ctx = _playCtx;
        _playCtx = null;
        ctx.onstatechange = null;
        try {
            const p = ctx.close();
            if (p && p.catch) p.catch(() => {});
        } catch {}
    }

    function _disconnectNodes(pb) {
        if (pb.source) { try { pb.source.disconnect(); } catch {} pb.source = null; }
        if (pb.gain) { try { pb.gain.disconnect(); } catch {} pb.gain = null; }
    }

    // Called for every remote audio track, also after a renegotiation or a
    // replaced peer connection: nodes are rebuilt for a new stream or track and
    // the stored preference is applied again.
    function _attachPlayback(userId, stream, track) {
        let pb = _playback.get(userId);
        if (!pb) {
            const el = document.createElement('audio');
            el.autoplay = true;
            el.id = `voice-audio-${userId}`;
            el.style.display = 'none';
            document.body.appendChild(el);
            pb = { el, stream: null, track: null, source: null, gain: null };
            _playback.set(userId, pb);
        }
        if (pb.stream !== stream || pb.track !== track || (!pb.gain && _webAudioWanted())) {
            _disconnectNodes(pb);
            pb.stream = stream;
            pb.track = track;
            pb.el.srcObject = stream;
            const ctx = _ensurePlayCtx();
            if (ctx) {
                try {
                    pb.source = ctx.createMediaStreamSource(stream);
                    pb.gain = ctx.createGain();
                    pb.source.connect(pb.gain);
                    pb.gain.connect(ctx.destination);
                } catch (e) {
                    console.warn('[Voice] Could not route audio through Web Audio:', e);
                    _disconnectNodes(pb);
                }
            }
        }
        _applyGain(userId);
    }

    function _detachPlayback(userId) {
        const pb = _playback.get(userId);
        if (!pb) return;
        _disconnectNodes(pb);
        pb.el.srcObject = null;
        pb.el.remove();
        _playback.delete(userId);
    }

    // The only place that sets how loud a peer is. Deafen and the local mute
    // both mean silence; otherwise the stored volume applies.
    function _applyGain(userId) {
        const pb = _playback.get(userId);
        if (!pb) return;
        const pref = _getPeerPref(userId);
        const silent = _deafened || pref.muted;
        const viaWebAudio = !!(pb.gain && _playCtx && _playCtx.state === 'running');
        if (viaWebAudio) {
            pb.gain.gain.value = silent ? 0 : Math.min(pref.vol, MAX_VOLUME) / 100;
            pb.el.muted = true;
        } else {
            if (pb.gain) pb.gain.gain.value = 0;
            const v = Math.min(pref.vol, MAX_VOLUME_ELEMENT) / 100;
            pb.el.volume = v;
            // iOS Safari ignores element.volume and reads back 1: remember it,
            // the popover then says that only the mute works there.
            if (v !== 1 && Math.abs(pb.el.volume - v) > 0.01) _volumeIgnored = true;
            pb.el.muted = silent || v === 0;
        }
    }

    function _applyAllGains() {
        for (const uid of _playback.keys()) _applyGain(uid);
    }

    // ---- Per-user preferences (localStorage, keyed by the peer's user id) ----
    function _validPeerId(userId) {
        const id = Number(userId);
        return Number.isInteger(id) && id > 0 ? id : null;
    }

    function _getPeerPref(userId) {
        return _peerPrefs.get(Number(userId)) || { vol: 100, muted: false };
    }

    // One entry per account that uses this browser, so two accounts on one
    // device do not share settings.
    function _storageKey() {
        return 'voice_peer_prefs_' + (_myUserId != null ? _myUserId : 'none');
    }

    function _loadPeerPrefs() {
        const key = _storageKey();
        if (_peerPrefsKey === key) return;
        _peerPrefsKey = key;
        _peerPrefs = new Map();
        try {
            const raw = localStorage.getItem(key);
            const data = raw ? JSON.parse(raw) : null;
            if (!data || typeof data !== 'object' || Array.isArray(data)) return;
            for (const k of Object.keys(data)) {
                if (_peerPrefs.size >= MAX_STORED_PEERS) break;
                const id = _validPeerId(k);
                const v = data[k];
                if (id === null || !v || typeof v !== 'object') continue;
                const vol = Math.round(Number(v.vol));
                const pref = {
                    vol: Number.isFinite(vol) ? Math.max(0, Math.min(MAX_VOLUME, vol)) : 100,
                    muted: v.muted === true
                };
                if (pref.vol !== 100 || pref.muted) _peerPrefs.set(id, pref);
            }
        } catch {}
    }

    function _savePeerPrefs() {
        try {
            if (!_peerPrefs.size) { localStorage.removeItem(_storageKey()); return; }
            const out = {};
            for (const [id, p] of _peerPrefs) out[id] = { vol: p.vol, muted: p.muted };
            localStorage.setItem(_storageKey(), JSON.stringify(out));
        } catch {}
    }

    function _setPeerPref(userId, patch) {
        const id = _validPeerId(userId);
        if (id === null || _isMe(id)) return false;
        const next = { ..._getPeerPref(id), ...patch };
        if (next.vol === 100 && !next.muted) _peerPrefs.delete(id);
        else if (_peerPrefs.has(id) || _peerPrefs.size < MAX_STORED_PEERS) _peerPrefs.set(id, next);
        else return false;
        _savePeerPrefs();
        _applyGain(id);
        _notifyState();
        return true;
    }

    function getPeerPref(userId) {
        const p = _getPeerPref(userId);
        return { volume: Math.min(p.vol, getMaxVolume()), muted: p.muted };
    }

    function setPeerVolume(userId, percent) {
        const n = Math.round(Number(percent));
        if (!Number.isFinite(n)) return false;
        return _setPeerPref(userId, { vol: Math.max(0, Math.min(getMaxVolume(), n)) });
    }

    function setPeerMuted(userId, muted) {
        return _setPeerPref(userId, { muted: !!muted });
    }

    function resetPeer(userId) {
        return _setPeerPref(userId, { vol: 100, muted: false });
    }

    function isInCall(userId) {
        return _inVoice && _voiceUsers.has(Number(userId)) && !_isMe(userId);
    }

    // ---- Per-user popover (plain DOM, outside every re-rendered container) ----
    const MENU_CSS = `
.voice-user-menu{position:fixed;z-index:10050;min-width:230px;max-width:min(92vw,320px);padding:.8rem;border-radius:6px;
background:var(--bg-secondary,#2f3136);color:var(--text-primary,#dcddde);border:1px solid var(--border-color,#4f545c);
box-shadow:0 6px 24px rgba(0,0,0,.45);font-size:.9rem}
.voice-user-menu .vum-title{font-weight:600;margin-bottom:.6rem;overflow-wrap:anywhere}
.voice-user-menu .vum-row{display:flex;align-items:center;gap:.6rem;margin-bottom:.6rem}
.voice-user-menu input[type=range]{flex:1;min-width:0}
.voice-user-menu .vum-pct{min-width:3.2em;text-align:right}
.voice-user-menu .vum-note{font-size:.75rem;color:var(--text-muted,#72767d);margin-bottom:.6rem}
.voice-user-menu .vum-actions{display:flex;gap:.5rem;flex-wrap:wrap}
.voice-user-menu button{padding:.4rem .7rem;border-radius:4px;cursor:pointer;font:inherit;
background:var(--bg-tertiary,#36393f);color:inherit;border:1px solid var(--border-color,#4f545c)}
.voice-user-menu button[aria-pressed="true"]{color:var(--accent-red,#f04747);border-color:var(--accent-red,#f04747)}
@media (pointer:coarse){.voice-user-menu button{min-height:44px}.voice-user-menu input[type=range]{min-height:44px}}
[data-voice-uid]{-webkit-touch-callout:none;-webkit-user-select:none;user-select:none}
`;

    function _ensureMenuStyle() {
        if (document.getElementById('voice-user-menu-style')) return;
        const st = document.createElement('style');
        st.id = 'voice-user-menu-style';
        st.textContent = MENU_CSS;
        (document.head || document.body).appendChild(st);
    }

    function _closeUserMenu(restoreFocus) {
        if (!_menu) return;
        const m = _menu;
        _menu = null;
        document.removeEventListener('keydown', m.onKey, true);
        document.removeEventListener('pointerdown', m.onDown, true);
        m.root.remove();
        if (restoreFocus) {
            // The tile may have been re-rendered since: find it again by id.
            let target = m.anchor && m.anchor.isConnected ? m.anchor : null;
            if (!target) target = document.querySelector(`[data-voice-uid="${m.uid}"]`);
            if (target && target.focus) target.focus();
        }
    }

    function _el(tag, cls, text) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    // Open the volume popover for a peer in the current call. `at` is {x, y}
    // from a pointer; without it the popover sits under the anchor element.
    function openUserMenu(userId, name, anchor, at) {
        const uid = _validPeerId(userId);
        if (uid === null || !isInCall(uid)) return false;
        if (_menu && _menu.uid === uid) {
            if (_menu.slider && _menu.slider.focus) _menu.slider.focus();
            return true;
        }
        _closeUserMenu();
        _ensureMenuStyle();
        _ensurePlayCtx();   // a gesture on the page: a suspended context may start now

        const label = String(name == null ? '' : name).slice(0, 80) || 'Participant';
        const root = _el('div', 'voice-user-menu');
        root.setAttribute('role', 'dialog');
        root.setAttribute('aria-label', 'Volume for ' + label);
        root.tabIndex = -1;
        root.appendChild(_el('div', 'vum-title', label));

        const max = getMaxVolume();
        const row = _el('div', 'vum-row');
        const slider = document.createElement('input');
        slider.type = 'range';
        slider.min = '0';
        slider.max = String(max);
        slider.step = '5';
        slider.id = `voice-user-menu-vol-${uid}`;
        slider.setAttribute('aria-label', 'Volume for ' + label);
        const pct = _el('span', 'vum-pct');
        pct.setAttribute('aria-live', 'polite');
        row.appendChild(slider);
        row.appendChild(pct);
        root.appendChild(row);
        const note = _el('div', 'vum-note');
        root.appendChild(note);

        const actions = _el('div', 'vum-actions');
        const muteBtn = _el('button', 'vum-mute', 'Mute for me');
        muteBtn.type = 'button';
        const resetBtn = _el('button', 'vum-reset', 'Reset');
        resetBtn.type = 'button';
        const closeBtn = _el('button', 'vum-close', 'Close');
        closeBtn.type = 'button';
        actions.appendChild(muteBtn);
        actions.appendChild(resetBtn);
        actions.appendChild(closeBtn);
        root.appendChild(actions);

        const refresh = () => {
            const p = getPeerPref(uid);
            slider.value = String(p.volume);
            pct.textContent = p.volume + '%';
            muteBtn.setAttribute('aria-pressed', p.muted ? 'true' : 'false');
            muteBtn.textContent = p.muted ? 'Unmute for me' : 'Mute for me';
            note.textContent = _volumeIgnored
                ? 'This device does not allow volume changes below 100%. Use Mute for me.'
                : (max < MAX_VOLUME ? 'Volume is capped at 100% on this device.' : '');
            note.style.display = note.textContent ? '' : 'none';
        };
        refresh();

        slider.addEventListener('input', () => {
            setPeerVolume(uid, slider.value);
            refresh();
        });
        muteBtn.addEventListener('click', () => { setPeerMuted(uid, !getPeerPref(uid).muted); refresh(); });
        resetBtn.addEventListener('click', () => { resetPeer(uid); refresh(); });
        closeBtn.addEventListener('click', () => _closeUserMenu(true));

        const onKey = (ev) => {
            if (ev.key === 'Escape') {
                ev.preventDefault();
                ev.stopPropagation();
                _closeUserMenu(true);
            } else if (ev.key === 'Tab') {
                // keep keyboard focus inside the popover while it is open
                const items = [slider, muteBtn, resetBtn, closeBtn];
                const i = items.indexOf(document.activeElement);
                const next = ev.shiftKey ? (i <= 0 ? items.length - 1 : i - 1) : (i === items.length - 1 ? 0 : i + 1);
                ev.preventDefault();
                items[next].focus();
            }
        };
        const onDown = (ev) => {
            if (!root.contains(ev.target)) _closeUserMenu(false);
        };
        document.addEventListener('keydown', onKey, true);
        document.addEventListener('pointerdown', onDown, true);

        document.body.appendChild(root);
        _menu = { uid, root, anchor, slider, onKey, onDown };

        // Place it: at the pointer, else under the anchor; kept inside the window.
        let x = 8, y = 8;
        if (at && Number.isFinite(at.x) && Number.isFinite(at.y)) { x = at.x; y = at.y; }
        else if (anchor && anchor.getBoundingClientRect) {
            const r = anchor.getBoundingClientRect();
            x = r.left; y = r.bottom + 4;
        }
        const w = root.offsetWidth || 260, h = root.offsetHeight || 160;
        const vw = window.innerWidth || 800, vh = window.innerHeight || 600;
        root.style.left = Math.max(8, Math.min(x, vw - w - 8)) + 'px';
        root.style.top = Math.max(8, Math.min(y, vh - h - 8)) + 'px';
        slider.focus();
        return true;
    }

    function closeUserMenu() { _closeUserMenu(true); }

    function _tileUid(container, target, selector) {
        const el = target && target.closest ? target.closest(selector) : null;
        if (!el || !container.contains(el)) return null;
        const raw = el.getAttribute('data-voice-uid');
        if (!/^\d+$/.test(raw || '')) return null;
        const uid = Number(raw);
        return isInCall(uid) ? { el, uid } : null;
    }

    // Wire a container (it stays in the page; its children may be re-rendered)
    // so that right-click, long-press, the context-menu key and Shift+F10 open
    // the popover for the child that carries data-voice-uid. opts.selector
    // picks those children, opts.nameFor(uid, el) gives the display name,
    // opts.enterOpens lets Enter open it on a focused child (Space is left
    // alone: it is the default push-to-talk key).
    function attachUserMenu(container, opts) {
        if (!container || container.__voiceMenuBound) return;
        container.__voiceMenuBound = true;
        _ensureMenuStyle();   // the no-callout rule must exist before the first long press
        const selector = (opts && opts.selector) || '[data-voice-uid]';
        const nameFor = (opts && opts.nameFor) || ((uid, el) => el.textContent.trim());
        const open = (hit, at) => openUserMenu(hit.uid, nameFor(hit.uid, hit.el), hit.el, at);

        container.addEventListener('contextmenu', (ev) => {
            const hit = _tileUid(container, ev.target, selector);
            if (!hit) return;       // not a peer in our call: leave the browser's own menu alone
            ev.preventDefault();
            const at = (ev.clientX || ev.clientY) ? { x: ev.clientX, y: ev.clientY } : null;
            open(hit, at);
        });

        container.addEventListener('keydown', (ev) => {
            const hit = _tileUid(container, ev.target, selector);
            if (!hit) return;
            const menuKey = ev.key === 'ContextMenu' || (ev.key === 'F10' && ev.shiftKey);
            const enter = opts && opts.enterOpens && ev.target === hit.el && ev.key === 'Enter';
            if (menuKey || enter) {
                ev.preventDefault();
                open(hit, null);
            }
        });

        // Long press (touch). The click that can follow it is swallowed so that
        // it does not also trigger the tile's own action (for example a mention).
        let timer = null, startX = 0, startY = 0, fired = false, swallowUntil = 0;
        const cancel = () => { if (timer) { clearTimeout(timer); timer = null; } };
        container.addEventListener('touchstart', (ev) => {
            cancel();
            fired = false;
            if (!ev.touches || ev.touches.length !== 1) return;
            const hit = _tileUid(container, ev.target, selector);
            if (!hit) return;
            startX = ev.touches[0].clientX;
            startY = ev.touches[0].clientY;
            timer = setTimeout(() => {
                timer = null;
                fired = true;
                open(hit, { x: startX, y: startY });
            }, 500);
        }, { passive: true });
        container.addEventListener('touchmove', (ev) => {
            const t = ev.touches && ev.touches[0];
            if (timer && t && (Math.abs(t.clientX - startX) > 10 || Math.abs(t.clientY - startY) > 10)) cancel();
        }, { passive: true });
        const end = () => {
            cancel();
            if (fired) swallowUntil = Date.now() + 700;
            fired = false;
        };
        container.addEventListener('touchend', end);
        container.addEventListener('touchcancel', end);
        container.addEventListener('click', (ev) => {
            if (Date.now() < swallowUntil) {
                swallowUntil = 0;
                ev.preventDefault();
                ev.stopPropagation();
            }
        }, true);
    }

    // Re-render a container that holds peer tiles without losing the keyboard
    // focus: the focused tile is found again by its id afterwards.
    function renderKeepingFocus(container, render) {
        const a = document.activeElement;
        const raw = a && container && container.contains(a) && a.getAttribute ? a.getAttribute('data-voice-uid') : null;
        render();
        if (raw && /^\d+$/.test(raw)) {
            const el = container.querySelector(`[data-voice-uid="${raw}"]`);
            if (el && el.focus) el.focus();
        }
    }

    // WebRTC peer management
    function _createPeerConnection(userId) {
        const pc = new RTCPeerConnection({ iceServers: _iceServers });

        // Add local audio tracks
        if (_localStream) {
            _localStream.getTracks().forEach(track => {
                pc.addTrack(track, _localStream);
            });
        }

        // Add screen share tracks if we're currently sharing
        if (_screenStream && _screenSharing) {
            const senders = [];
            _screenStream.getTracks().forEach(track => {
                senders.push(pc.addTrack(track, _screenStream));
            });
            _screenSenders.set(userId, senders);
        }

        // ICE candidates
        pc.onicecandidate = (e) => {
            if (e.candidate && _ws && _ws.readyState === WebSocket.OPEN) {
                _ws.send(JSON.stringify({
                    type: 'voice_signal',
                    target_user_id: userId,
                    signal: { type: 'ice-candidate', candidate: e.candidate }
                }));
            }
        };

        // Renegotiation (fires when tracks are added/removed, only in stable state)
        pc.onnegotiationneeded = async () => {
            if (_makingOffer.has(userId)) return;
            _makingOffer.add(userId);
            try {
                const offer = await pc.createOffer();
                await pc.setLocalDescription(offer);
                if (_ws && _ws.readyState === WebSocket.OPEN) {
                    _ws.send(JSON.stringify({
                        type: 'voice_signal',
                        target_user_id: userId,
                        signal: { type: 'offer', sdp: offer.sdp }
                    }));
                }
            } catch (e) {
                console.error(`[Voice] Renegotiation failed for ${userId}:`, e);
            } finally {
                _makingOffer.delete(userId);
            }
        };

        // Remote tracks (audio + video)
        pc.ontrack = (e) => {
            if (e.track.kind === 'audio') {
                let stream = e.streams && e.streams[0];
                if (!stream && typeof MediaStream !== 'undefined') stream = new MediaStream([e.track]);
                if (stream) _attachPlayback(userId, stream, e.track);
            } else if (e.track.kind === 'video') {
                // Screen share video track received
                if (_onScreenShareChange) {
                    _onScreenShareChange({
                        action: 'track',
                        userId: userId,
                        stream: e.streams[0],
                        track: e.track
                    });
                }
                // Auto-hide when track ends
                e.track.onended = () => {
                    if (_onScreenShareChange) {
                        _onScreenShareChange({
                            action: 'track_ended',
                            userId: userId
                        });
                    }
                };
            }
        };

        // Connection state monitoring
        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'failed') {
                console.warn(`[Voice] Peer ${userId} connection failed, attempting restart`);
                pc.restartIce();
            } else if (pc.connectionState === 'disconnected') {
                console.warn(`[Voice] Peer ${userId} disconnected`);
            }
        };

        _peers.set(userId, pc);
        return pc;
    }

    // Signal handlers
    function _handleVoiceState(data) {
        // Initial state on join — list of existing voice users. The same message
        // answers a resume (data.resumed), then only peers that are not connected
        // are negotiated again.
        const resumed = !!data.resumed;
        if (data.resume_token) _resumeToken = data.resume_token;
        if (data.channel) _room = data.channel;
        if (resumed) {
            _reconnecting = false;
            _clearGiveUp();
        }
        _voiceUsers.clear();
        _screenSharerId = null;
        for (const u of (data.users || [])) {
            _voiceUsers.set(u.user_id, {
                username: u.username,
                muted: u.muted,
                deafened: u.deafened,
                speaking: u.speaking,
                screen_sharing: u.screen_sharing || false,
                reconnecting: !!u.reconnecting
            });
            if (u.screen_sharing) _screenSharerId = u.user_id;
        }
        // Create peer connections to existing users (we're the offerer)
        for (const u of (data.users || [])) {
            // Don't create a peer to ourselves
            if (_isMe(u.user_id)) continue;
            // A member that is reconnecting cannot receive our offer; they offer
            // to us when they are back.
            if (u.reconnecting) continue;
            const pc = _peers.get(u.user_id);
            if (pc) {
                if (resumed && pc.connectionState !== 'connected') _createAndOffer(u.user_id);
                continue;
            }
            _createAndOffer(u.user_id);
        }
        if (resumed) _resendLocalState();
        _notifyState();
    }

    // Mute, deafen and speaking changes made while the socket was down never
    // reached the server; tell it where we are now.
    function _resendLocalState() {
        if (!_ws || _ws.readyState !== WebSocket.OPEN) return;
        _ws.send(JSON.stringify({ type: 'voice_mute', muted: _muted }));
        _ws.send(JSON.stringify({ type: 'voice_deafen', deafened: _deafened }));
        _ws.send(JSON.stringify({ type: 'voice_speaking', speaking: _speaking }));
    }

    function _setUserReconnecting(userId, value) {
        const user = _voiceUsers.get(userId);
        if (user) user.reconnecting = value;
        _notifyState();
    }

    // Close one peer connection and everything hanging off it.
    function _dropPeer(userId) {
        const pc = _peers.get(userId);
        if (pc) {
            pc.onicecandidate = null;
            pc.onnegotiationneeded = null;
            pc.ontrack = null;
            pc.onconnectionstatechange = null;
            pc.close();
            _peers.delete(userId);
        }
        _detachPlayback(userId);
        _screenSenders.delete(userId);
        _pendingCandidates.delete(userId);
        _makingOffer.delete(userId);
    }

    function _isMe(userId) {
        return _myUserId !== null && Number(userId) === _myUserId;
    }

    async function _createAndOffer(userId) {
        // Start from nothing: a stale connection to this user is thrown away
        // here, and the "fresh" flag makes the other side do the same.
        _dropPeer(userId);
        _makingOffer.add(userId);
        const pc = _createPeerConnection(userId);
        try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            if (_ws && _ws.readyState === WebSocket.OPEN) {
                _ws.send(JSON.stringify({
                    type: 'voice_signal',
                    target_user_id: userId,
                    signal: { type: 'offer', sdp: offer.sdp, fresh: true }
                }));
            }
        } catch (e) {
            console.error(`[Voice] Failed to create offer for ${userId}:`, e);
        } finally {
            _makingOffer.delete(userId);
        }
    }

    async function _handleUserJoined(data) {
        const userId = data.user_id;
        _voiceUsers.set(userId, {
            username: data.username,
            muted: false, deafened: false, speaking: false, screen_sharing: false,
            reconnecting: false
        });
        // The new joiner will receive voice_state and create offers to us
        // We wait for their offer — no action needed here
        _notifyState();
    }

    function _handleUserLeft(data) {
        const userId = data.user_id;
        // If the user who left was screen sharing, clear it
        if (_screenSharerId === userId) {
            _screenSharerId = null;
            if (_onScreenShareChange) {
                _onScreenShareChange({ action: 'stopped', userId });
            }
        }
        _voiceUsers.delete(userId);
        _dropPeer(userId);
        if (_menu && _menu.uid === Number(userId)) _closeUserMenu();
        _notifyState();
    }

    async function _handleSignal(data) {
        const fromId = data.from_user_id;
        const signal = data.signal;
        if (!signal) return;
        if (_isMe(fromId)) return; // Ignore self-signals

        if (signal.type === 'offer') {
            // "Polite peer" pattern: lower user_id is polite (yields on glare)
            const polite = _myUserId !== null && _myUserId < fromId;
            const offerCollision = _makingOffer.has(fromId) ||
                (_peers.get(fromId)?.signalingState !== 'stable' && _peers.has(fromId));

            // A fresh offer (join, or resume after a dropped connection) replaces
            // whatever we had with that user, so it is never a collision.
            if (signal.fresh) _dropPeer(fromId);

            if (!signal.fresh && !polite && offerCollision) {
                // Impolite peer ignores incoming offer during glare
                return;
            }

            let pc = _peers.get(fromId);
            const isNewPc = !pc;
            if (isNewPc) {
                // Guard: prevent onnegotiationneeded from creating a competing
                // offer while we handle this incoming offer on the new PC
                _makingOffer.add(fromId);
                pc = _createPeerConnection(fromId);
            }

            try {
                // If we have a pending local offer (glare), rollback first
                if (pc.signalingState === 'have-local-offer') {
                    await pc.setLocalDescription({ type: 'rollback' });
                }
                await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: signal.sdp }));
                // Flush buffered candidates
                const buffered = _pendingCandidates.get(fromId) || [];
                _pendingCandidates.delete(fromId);
                for (const c of buffered) {
                    await pc.addIceCandidate(new RTCIceCandidate(c)).catch(() => {});
                }
                const answer = await pc.createAnswer();
                await pc.setLocalDescription(answer);
                if (_ws && _ws.readyState === WebSocket.OPEN) {
                    _ws.send(JSON.stringify({
                        type: 'voice_signal',
                        target_user_id: fromId,
                        signal: { type: 'answer', sdp: answer.sdp }
                    }));
                }
            } catch (e) {
                console.error(`[Voice] Failed to handle offer from ${fromId}:`, e);
            } finally {
                if (isNewPc) _makingOffer.delete(fromId);
            }
        } else if (signal.type === 'answer') {
            const pc = _peers.get(fromId);
            if (pc) {
                try {
                    await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: signal.sdp }));
                    // Flush buffered candidates
                    const buffered = _pendingCandidates.get(fromId) || [];
                    _pendingCandidates.delete(fromId);
                    for (const c of buffered) {
                        await pc.addIceCandidate(new RTCIceCandidate(c)).catch(() => {});
                    }
                } catch (e) {
                    console.error(`[Voice] Failed to set answer from ${fromId}:`, e);
                }
            }
        } else if (signal.type === 'ice-candidate') {
            const pc = _peers.get(fromId);
            if (pc && pc.remoteDescription) {
                try {
                    await pc.addIceCandidate(new RTCIceCandidate(signal.candidate));
                } catch (e) {
                    console.warn(`[Voice] Failed to add ICE candidate:`, e);
                }
            } else {
                // Buffer candidate until remote description is set
                if (!_pendingCandidates.has(fromId)) _pendingCandidates.set(fromId, []);
                _pendingCandidates.get(fromId).push(signal.candidate);
            }
        }
    }

    function _handleScreenShareStarted(data) {
        _screenSharerId = data.user_id;
        const user = _voiceUsers.get(data.user_id);
        if (user) user.screen_sharing = true;
        if (_onScreenShareChange) {
            const event = {
                action: 'started',
                userId: data.user_id,
                username: data.username
            };
            // For the sharer: provide local screen stream so they can preview
            if (_isMe(data.user_id) && _screenStream) {
                event.stream = _screenStream;
                event.isSelf = true;
            }
            _onScreenShareChange(event);
        }
        _notifyState();
    }

    function _handleScreenShareStopped(data) {
        _screenSharerId = null;
        const user = _voiceUsers.get(data.user_id);
        if (user) user.screen_sharing = false;
        if (_onScreenShareChange) {
            _onScreenShareChange({
                action: 'stopped',
                userId: data.user_id
            });
        }
        _notifyState();
    }

    async function startScreenShare() {
        if (!_inVoice || _screenSharing) return;
        if (_screenSharerId) {
            console.warn('[Voice] Someone else is already sharing');
            return;
        }
        if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
            console.error('[Voice] Screen sharing not supported');
            return;
        }

        try {
            _screenStream = await navigator.mediaDevices.getDisplayMedia({
                video: { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 15 } },
                audio: true
            });
        } catch (e) {
            console.warn('[Voice] Screen share cancelled or denied:', e);
            return;
        }

        _screenSharing = true;

        // Handle browser's native "Stop sharing" button
        _screenStream.getVideoTracks().forEach(track => {
            track.onended = () => stopScreenShare();
        });

        // Send screen_share_start to server
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'screen_share_start' }));
        }

        // Add screen tracks to all existing peer connections
        for (const [userId, pc] of _peers) {
            const senders = [];
            _screenStream.getTracks().forEach(track => {
                senders.push(pc.addTrack(track, _screenStream));
            });
            _screenSenders.set(userId, senders);
            // onnegotiationneeded will fire automatically
        }

        _notifyState();
    }

    function stopScreenShare() {
        if (!_screenSharing) return;

        // Send screen_share_stop to server
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'screen_share_stop' }));
        }

        // Remove screen tracks from all peers
        for (const [userId, senders] of _screenSenders) {
            const pc = _peers.get(userId);
            if (pc) {
                for (const sender of senders) {
                    try { pc.removeTrack(sender); } catch (e) {}
                }
            }
        }
        _screenSenders.clear();

        // Stop screen stream
        if (_screenStream) {
            _screenStream.getTracks().forEach(t => t.stop());
            _screenStream = null;
        }

        _screenSharing = false;
        _notifyState();
    }

    function _handleMuteChanged(data) {
        const user = _voiceUsers.get(data.user_id);
        if (user) user.muted = data.muted;
        _notifyState();
    }

    function _handleDeafenChanged(data) {
        const user = _voiceUsers.get(data.user_id);
        if (user) user.deafened = data.deafened;
        _notifyState();
    }

    function _handleSpeakingChanged(data) {
        const user = _voiceUsers.get(data.user_id);
        if (user) user.speaking = data.speaking;
        _notifyState();
    }

    function _notifyState() {
        if (_onStateChange) {
            _onStateChange({
                inVoice: _inVoice,
                reconnecting: _reconnecting,
                muted: _muted,
                deafened: _deafened,
                speaking: _speaking,
                screenSharing: _screenSharing,
                screenSharerId: _screenSharerId,
                mode: _prefs.mode,
                pttKey: _prefs.pttKey,
                vadThreshold: _prefs.vadThreshold,
                users: _stateUsers()
            });
        }
    }

    function getState() {
        return {
            inVoice: _inVoice,
            reconnecting: _reconnecting,
            muted: _muted,
            deafened: _deafened,
            speaking: _speaking,
            screenSharing: _screenSharing,
            screenSharerId: _screenSharerId,
            mode: _prefs.mode,
            pttKey: _prefs.pttKey,
            vadThreshold: _prefs.vadThreshold,
            users: _stateUsers()
        };
    }

    function _stateUsers() {
        return Array.from(_voiceUsers.entries()).map(([id, u]) => {
            const p = _getPeerPref(id);
            return { user_id: id, ...u, local_volume: p.vol, local_muted: p.muted };
        });
    }

    function getPrefs() { return { ..._prefs }; }

    function isInVoice() { return _inVoice; }

    // Clean up when navigating away
    if (typeof window !== 'undefined') {
        window.addEventListener('beforeunload', () => {
            if (_inVoice) leave();
        });
    }

    return {
        init,
        handleMessage,
        join,
        leave,
        toggleMute,
        toggleDeafen,
        setMode,
        setPttKey,
        setVadThreshold,
        getState,
        getPrefs,
        isInVoice,
        startScreenShare,
        stopScreenShare,
        getMaxVolume,
        getPeerPref,
        setPeerVolume,
        setPeerMuted,
        resetPeer,
        isInCall,
        openUserMenu,
        closeUserMenu,
        attachUserMenu,
        renderKeepingFocus
    };
})();
