/* Stream card thumbnails: retry a failed load, then show the placeholder.
 *
 * The thumbnail route answers 503 (with Retry-After) when the server is already
 * capturing at its limit, so a card that fails is tried again up to 3 times, after
 * 2 s, 4 s and 8 s, each time with a new query value so the browser does not reuse
 * the failed answer. Only after the last failure the placeholder replaces the image.
 * Used as: <img src="..." onerror="thumbError(this)"> followed by the placeholder.
 */
(function () {
    var DELAYS_MS = [2000, 4000, 8000];

    function showPlaceholder(img) {
        img.style.display = 'none';
        var ph = img.nextElementSibling;
        if (ph) ph.style.display = 'flex';
    }

    window.thumbError = function (img) {
        var tries = parseInt(img.dataset.thumbTries || '0', 10);
        if (tries >= DELAYS_MS.length) {
            showPlaceholder(img);
            return;
        }
        img.dataset.thumbTries = String(tries + 1);
        setTimeout(function () {
            // the grid is rebuilt every 30 s; a card that is gone needs no retry
            if (!img.isConnected) return;
            var url = new URL(img.getAttribute('src'), window.location.href);
            url.searchParams.set('r', String(Date.now()));
            img.src = url.href;
        }, DELAYS_MS[tries]);
    };
})();
