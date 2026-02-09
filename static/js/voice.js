/**
 * Voice Chat Module — WebRTC P2P mesh voice chat
 * Piggybacks signaling on existing /ws/chat WebSocket.
 * Supports VAD (Voice Activity Detection) and PTT (Push-to-Talk).
 */
const VoiceChat = (() => {
    // State
    let _ws = null;
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
    let _prefs = { mode: 'vad', pttKey: 'Space', vadThreshold: -50, noiseGate: true };
    let _pttActive = false;
    let _pendingCandidates = new Map(); // user_id -> [candidates] (buffered before remote desc set)

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

    function init(ws, onStateChange) {
        _ws = ws;
        _onStateChange = onStateChange || null;
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
        }
    }

    async function join() {
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

        // Send join to server
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type: 'voice_join' }));
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

        // Add local tracks
        if (_localStream) {
            _localStream.getTracks().forEach(track => {
                pc.addTrack(track, _localStream);
            });
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

        // Remote track
        pc.ontrack = (e) => {
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
        for (const u of (data.users || [])) {
            _voiceUsers.set(u.user_id, {
                username: u.username,
                muted: u.muted,
                deafened: u.deafened,
                speaking: u.speaking
            });
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
        // Check by comparing with our voice state
        // The server sends us in the users list too
        return false; // We rely on the server not forwarding signals to ourselves
    }

    async function _createAndOffer(userId) {
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
        }
    }

    async function _handleUserJoined(data) {
        const userId = data.user_id;
        _voiceUsers.set(userId, {
            username: data.username,
            muted: false, deafened: false, speaking: false
        });
        // The new joiner will receive voice_state and create offers to us
        // We wait for their offer — no action needed here
        _notifyState();
    }

    function _handleUserLeft(data) {
        const userId = data.user_id;
        _voiceUsers.delete(userId);
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

        if (signal.type === 'offer') {
            // Received offer — create answer
            let pc = _peers.get(fromId);
            if (pc) { pc.close(); _peers.delete(fromId); }
            pc = _createPeerConnection(fromId);
            try {
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
        isInVoice
    };
})();
