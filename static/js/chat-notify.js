/* Chat notification helpers: per-channel level and mute, the notification sound, quiet
 * hours, the lock that keeps several tabs from all playing it, the one-time move of the old
 * starred channels, and the text of a desktop alert. Pure functions where possible so they can
 * be tested under Node (tests/chat_notify_harness.js). No network except the PUT calls the
 * caller hands in, and no external file: the sound is made with WebAudio.
 *
 * A channel row from /api/chat/channels carries notify_level (null = default) and
 * muted_until (epoch seconds, 0 = not muted).
 */
(function (root) {
    'use strict';

    var SOUND_KEY = 'portal_chat_sound';
    var SOUND_LAST_KEY = 'portal_chat_sound_last';
    var STAR_KEY = 'portal_notif_channels';
    var LOCK_MS = 1500;

    function isMuted(ch, nowMs) {
        var until = Number(ch && ch.muted_until) || 0;
        return until > 0 && until * 1000 > (nowMs == null ? Date.now() : nowMs);
    }

    /* What the badge of a channel the member is not in shows:
     * 'none' (level none or muted), 'mentions' (only mentions count), 'all' (every message). */
    function badgeMode(ch, nowMs) {
        if (!ch) return 'all';
        if (ch.notify_level === 'none' || isMuted(ch, nowMs)) return 'none';
        if (ch.notify_level === 'mentions') return 'mentions';
        return 'all';
    }

    /* Sound and desktop alert: an ordinary message only on a channel the member set to All
     * (and did not mute); a mention unless the level is none. A mute does not stop a mention. */
    function alertWanted(ch, isMention, nowMs) {
        var level = ch ? ch.notify_level : null;
        if (level === 'none') return false;
        if (isMention) return true;
        return level === 'all' && !isMuted(ch, nowMs);
    }

    function _minutes(text, fallback) {
        var m = /^(\d{1,2}):(\d{2})$/.exec(String(text || ''));
        if (!m) return fallback;
        var h = Number(m[1]), mm = Number(m[2]);
        if (h > 23 || mm > 59) return fallback;
        return h * 60 + mm;
    }

    /* Quiet hours {quiet: bool, start: 'HH:MM', end: 'HH:MM'}; a window that passes midnight
     * (22:00 to 07:00) is handled. Equal start and end mean no quiet window. */
    function inQuietHours(settings, date) {
        if (!settings || !settings.quiet) return false;
        var s = _minutes(settings.start, 22 * 60), e = _minutes(settings.end, 7 * 60);
        if (s === e) return false;
        var d = date || new Date();
        var now = d.getHours() * 60 + d.getMinutes();
        return s < e ? (now >= s && now < e) : (now >= s || now < e);
    }

    function readSoundSettings(storage) {
        var out = { enabled: true, quiet: false, start: '22:00', end: '07:00' };
        try {
            var raw = JSON.parse(storage.getItem(SOUND_KEY) || '{}');
            if (raw && typeof raw === 'object') {
                if (typeof raw.enabled === 'boolean') out.enabled = raw.enabled;
                if (typeof raw.quiet === 'boolean') out.quiet = raw.quiet;
                if (_minutes(raw.start, -1) >= 0) out.start = raw.start;
                if (_minutes(raw.end, -1) >= 0) out.end = raw.end;
            }
        } catch (e) { /* keep defaults */ }
        return out;
    }

    function writeSoundSettings(storage, settings) {
        var s = readSoundSettings({ getItem: function () { return JSON.stringify(settings); } });
        try { storage.setItem(SOUND_KEY, JSON.stringify(s)); } catch (e) { /* ignore */ }
        return s;
    }

    /* Whether a sound may play now: switched on and outside quiet hours. */
    function soundAllowed(storage, date) {
        var s = readSoundSettings(storage);
        return s.enabled && !inQuietHours(s, date);
    }

    /* Several tabs get the same frame: only one plays. navigator.locks (ifAvailable, held for
     * LOCK_MS) where the browser has it; otherwise a timestamp in localStorage that a tab must
     * find older than LOCK_MS before it writes its own. Resolves true for the tab that plays. */
    function claimSound(env) {
        var nav = env.navigator, storage = env.storage, now = env.now ? env.now() : Date.now();
        if (nav && nav.locks && typeof nav.locks.request === 'function') {
            return new Promise(function (resolve) {
                nav.locks.request('portal-chat-sound', { ifAvailable: true }, function (lock) {
                    if (!lock) { resolve(false); return null; }
                    resolve(true);
                    return new Promise(function (release) { (env.setTimeout || setTimeout)(release, LOCK_MS); });
                }).catch(function () { resolve(false); });
            });
        }
        try {
            var last = Number(storage.getItem(SOUND_LAST_KEY)) || 0;
            if (now - last < LOCK_MS && now >= last) return Promise.resolve(false);
            storage.setItem(SOUND_LAST_KEY, String(now));
        } catch (e) { /* storage unavailable: play */ }
        return Promise.resolve(true);
    }

    var _ctx = null;
    function _audioContext(win) {
        var AC = win && (win.AudioContext || win.webkitAudioContext);
        if (!AC) return null;
        if (!_ctx) { try { _ctx = new AC(); } catch (e) { return null; } }
        return _ctx;
    }

    /* A short two-note tone. The context starts suspended until a click or key, so call
     * unlockAudio from the first such event. */
    function beep(win) {
        var ctx = _audioContext(win);
        if (!ctx) return false;
        try {
            if (ctx.state === 'suspended' && ctx.resume) ctx.resume();
            var t = ctx.currentTime;
            [[880, 0], [1175, 0.12]].forEach(function (n) {
                var osc = ctx.createOscillator(), gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.value = n[0];
                gain.gain.setValueAtTime(0.0001, t + n[1]);
                gain.gain.exponentialRampToValueAtTime(0.15, t + n[1] + 0.02);
                gain.gain.exponentialRampToValueAtTime(0.0001, t + n[1] + 0.14);
                osc.connect(gain); gain.connect(ctx.destination);
                osc.start(t + n[1]); osc.stop(t + n[1] + 0.16);
            });
            return true;
        } catch (e) { return false; }
    }

    function unlockAudio(win) {
        var ctx = _audioContext(win);
        if (ctx && ctx.state === 'suspended' && ctx.resume) { try { ctx.resume(); } catch (e) { /* ignore */ } }
    }

    /* Play once for this member across tabs, if the settings allow it. Resolves true when played. */
    function playSound(env) {
        if (!soundAllowed(env.storage, env.date)) return Promise.resolve(false);
        return claimSound(env).then(function (mine) {
            return mine ? beep(env.window) : false;
        });
    }

    /* The text of a desktop alert for a message frame. The channel comes from the frame
     * (channel, channel_id), never from the channel the page is showing: after a switch the
     * socket may still deliver a frame of the room it is leaving. Returns null when the frame
     * does not say which channel it is from. */
    function channelAlert(frame, channels) {
        if (!frame || !frame.channel) return null;
        var name = String(frame.channel);
        var text = frame.message || (frame.image_url ? '[image]' : '[attachment]');
        return {
            channel: name,
            channelId: frame.channel_id == null ? null : frame.channel_id,
            title: '#' + name + ' — ' + (frame.username || 'Someone'),
            body: text.length > 120 ? text.slice(0, 120) + '…' : text,
            tag: 'portal-channel-' + (frame.channel_id != null ? frame.channel_id : name)
        };
    }

    /* The old per-channel star lived in localStorage under portal_notif_channels (a list of
     * channel names). Each starred channel that still exists becomes level All on the server,
     * once. A channel whose PUT failed stays in the list for the next page load; the key is
     * removed when nothing is left. put(channelId, body) returns a promise of a boolean. */
    function migrateStars(storage, channels, put) {
        var names;
        try { names = JSON.parse(storage.getItem(STAR_KEY) || 'null'); } catch (e) { names = null; }
        if (!Array.isArray(names)) {
            try { storage.removeItem(STAR_KEY); } catch (e) { /* ignore */ }
            return Promise.resolve(0);
        }
        var byName = {};
        (channels || []).forEach(function (c) { byName[c.name] = c; });
        var left = [], jobs = [];
        names.forEach(function (n) {
            var ch = byName[n];
            if (!ch) return;                                   // gone or not readable any more: drop
            if (ch.notify_level) return;                       // already chosen on the server
            jobs.push(Promise.resolve(put(ch.id, { level: 'all' })).then(function (ok) {
                if (ok) { ch.notify_level = 'all'; } else { left.push(n); }
            }, function () { left.push(n); }));
        });
        return Promise.all(jobs).then(function () {
            try {
                if (left.length) storage.setItem(STAR_KEY, JSON.stringify(left)); else storage.removeItem(STAR_KEY);
            } catch (e) { /* ignore */ }
            return jobs.length - left.length;
        });
    }

    var api = {
        MUTE_CHOICES: [1, 8, 24],
        isMuted: isMuted, badgeMode: badgeMode, alertWanted: alertWanted,
        inQuietHours: inQuietHours, readSoundSettings: readSoundSettings,
        writeSoundSettings: writeSoundSettings, soundAllowed: soundAllowed,
        claimSound: claimSound, playSound: playSound, unlockAudio: unlockAudio, beep: beep,
        channelAlert: channelAlert, migrateStars: migrateStars
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.ChatNotify = api;
})(typeof window !== 'undefined' ? window : globalThis);
