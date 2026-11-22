/* Retry countdown for the page the portal shows when a service cannot be reached
   (server.py _upstream_error_page). Loaded from a file so the page needs no inline script. */
(function () {
    'use strict';
    var box = document.getElementById('upstream-error');
    if (!box) return;
    var left = parseInt(box.getAttribute('data-retry'), 10);
    if (!(left > 0)) left = 15;
    var auto = box.getAttribute('data-auto') === '1';
    var label = document.getElementById('upstream-error-countdown');
    var button = document.getElementById('upstream-error-retry');
    var home = document.getElementById('upstream-error-home');
    // Inside the embedded browser's frame (sandboxed, no top navigation) the link opens in a new tab.
    if (home && window.top !== window.self) {
        home.setAttribute('target', '_blank');
        home.setAttribute('rel', 'noopener');
    }

    // A maintenance page names its end time in UTC; show it in the member's own time zone.
    var detail = document.getElementById('upstream-error-detail');
    var until = detail && detail.getAttribute('data-until');
    if (until) {
        var when = new Date(until);
        if (!isNaN(when.getTime())) {
            var now = new Date();
            var sameDay = when.toDateString() === now.toDateString();
            var opts = { hour: '2-digit', minute: '2-digit' };
            var text = sameDay ? when.toLocaleTimeString([], opts)
                : when.toLocaleDateString([], { year: 'numeric', month: '2-digit', day: '2-digit' }) + ' ' + when.toLocaleTimeString([], opts);
            detail.textContent = 'Down for maintenance until ' + text;
        }
    }

    function reload() { window.location.reload(); }
    if (button) button.addEventListener('click', reload);
    if (!auto) {
        if (label) label.textContent = 'This request is not repeated automatically.';
        return;
    }
    function show() {
        if (label) label.textContent = 'Trying again in ' + left + ' s';
    }
    show();
    var timer = setInterval(function () {
        left -= 1;
        if (left > 0) { show(); return; }
        clearInterval(timer);
        if (label) label.textContent = 'Trying again...';
        if (document.hidden) {
            document.addEventListener('visibilitychange', function once() {
                if (!document.hidden) { document.removeEventListener('visibilitychange', once); reload(); }
            });
        } else {
            reload();
        }
    }, 1000);
})();
