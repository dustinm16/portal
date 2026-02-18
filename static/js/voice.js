/**
 * Voice Chat Module — WebRTC P2P mesh voice chat
 * Piggybacks signaling on existing /ws/chat WebSocket.
 * Supports VAD (Voice Activity Detection) and PTT (Push-to-Talk).
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
    let _audioElements = new Map(); // user_id -> <audio>
    let _voiceUsers = new Map();  // user_id -> {username, muted, deafened, speaking}
    let _onStateChange = null;    // callback for UI updates
    let _onScreenShareChange = null; // callback for screen share UI
    let _prefs = { mode: 'vad', pttKey: 'Space', vadThreshold: -50, noiseGate: true };
    let _pttActive = false;
    let _pendingCandidates = new Map(); // user_id -> [candidates] (buffered before remote desc set)
    let _makingOffer = new Set();  // user_ids we're currently creating offers for

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
        _myUserId = myUserId || null;
        _onStateChange = onStateChange || null;
        _onScreenShareChange = onScreenShareChange || null;
        _loadPrefs();
        _fetchIceServers();
    }

    function handleMessage(data) {
        const type = data.type;
        if (type === 'voice_state') {
            _handleVoiceState(data);
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
        }
        _cleanup();
        _notifyState();
    }

    function _cleanup() {
        _inVoice = false;
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

        // Remove audio elements
        for (const [uid, el] of _audioElements) {
            el.srcObject = null;
            el.remove();
        }
        _audioElements.clear();
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
        // Deafen: mute all remote audio elements
        for (const [uid, el] of _audioElements) {
            el.muted = _deafened;
        }
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
                let audio = _audioElements.get(userId);
                if (!audio) {
                    audio = document.createElement('audio');
                    audio.autoplay = true;
                    audio.id = `voice-audio-${userId}`;
                    audio.style.display = 'none';
                    document.body.appendChild(audio);
                    _audioElements.set(userId, audio);
                }
                audio.srcObject = e.streams[0];
                audio.muted = _deafened;
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
        // Initial state on join — list of existing voice users
        _voiceUsers.clear();
        _screenSharerId = null;
        for (const u of (data.users || [])) {
            _voiceUsers.set(u.user_id, {
                username: u.username,
                muted: u.muted,
                deafened: u.deafened,
                speaking: u.speaking,
                screen_sharing: u.screen_sharing || false
            });
            if (u.screen_sharing) _screenSharerId = u.user_id;
        }
        // Create peer connections to existing users (we're the offerer)
        for (const u of (data.users || [])) {
            if (_peers.has(u.user_id)) continue;
            // Don't create a peer to ourselves
            if (_isMe(u.user_id)) continue;
            _createAndOffer(u.user_id);
        }
        _notifyState();
    }

    function _isMe(userId) {
        return _myUserId !== null && userId === _myUserId;
    }

    async function _createAndOffer(userId) {
        _makingOffer.add(userId);
        const pc = _createPeerConnection(userId);
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
            console.error(`[Voice] Failed to create offer for ${userId}:`, e);
        } finally {
            _makingOffer.delete(userId);
        }
    }

    async function _handleUserJoined(data) {
        const userId = data.user_id;
        _voiceUsers.set(userId, {
            username: data.username,
            muted: false, deafened: false, speaking: false, screen_sharing: false
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
        _screenSenders.delete(userId);
        // Close peer
        const pc = _peers.get(userId);
        if (pc) { pc.close(); _peers.delete(userId); }
        // Remove audio
        const audio = _audioElements.get(userId);
        if (audio) { audio.srcObject = null; audio.remove(); _audioElements.delete(userId); }
        _pendingCandidates.delete(userId);
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

            if (!polite && offerCollision) {
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
                muted: _muted,
                deafened: _deafened,
                speaking: _speaking,
                screenSharing: _screenSharing,
                screenSharerId: _screenSharerId,
                mode: _prefs.mode,
                pttKey: _prefs.pttKey,
                vadThreshold: _prefs.vadThreshold,
                users: Array.from(_voiceUsers.entries()).map(([id, u]) => ({
                    user_id: id, ...u
                }))
            });
        }
    }

    function getState() {
        return {
            inVoice: _inVoice,
            muted: _muted,
            deafened: _deafened,
            speaking: _speaking,
            screenSharing: _screenSharing,
            screenSharerId: _screenSharerId,
            mode: _prefs.mode,
            pttKey: _prefs.pttKey,
            vadThreshold: _prefs.vadThreshold,
            users: Array.from(_voiceUsers.entries()).map(([id, u]) => ({
                user_id: id, ...u
            }))
        };
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
        stopScreenShare
    };
})();
