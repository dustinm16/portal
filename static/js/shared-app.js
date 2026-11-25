/* The first-open notice of a web connection somebody shared (release 1.24.1).
   Continue records the choice for this connection (POST /api/connections/{id}/notice) and goes on to the
   address the server checked; Cancel goes back to the dashboard. */
(function () {
    'use strict';
    var box = document.getElementById('notice');
    var errorEl = document.getElementById('shared-error');
    var go = document.getElementById('shared-continue');
    var cancel = document.getElementById('shared-cancel');
    if (!box || !go || !cancel) return;

    cancel.addEventListener('click', function () { window.location.href = '/dashboard'; });
    go.addEventListener('click', function () {
        go.disabled = true;
        errorEl.hidden = true;
        fetch('/api/connections/' + encodeURIComponent(box.dataset.connection) + '/notice', {
            method: 'POST', credentials: 'same-origin', headers: { 'Accept': 'application/json' }
        }).then(function (r) {
            if (!r.ok) throw new Error('The choice could not be saved (' + r.status + ')');
            window.location.replace(box.dataset.next);
        }).catch(function (e) {
            go.disabled = false;
            errorEl.textContent = e.message || 'The choice could not be saved';
            errorEl.hidden = false;
        });
    });
})();
