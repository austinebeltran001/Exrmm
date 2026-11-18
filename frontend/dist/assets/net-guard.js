// EX 313 LTD - portal resilience guard (loaded first, before the dashboard).
//
// Problem this fixes: when the portal is opened through a gateway, tunnel,
// port-forward or client-side proxy, a momentary hiccup makes the path answer
// an /api/ request with an HTML page (for example a document titled
// "Unable to connect to <host>:<port>"). The dashboard extensions called
// res.text() and dropped that HTML straight into their error modals, so the
// operator saw a wall of markup instead of "try again" - and the action they
// clicked never ran.
//
// This guard only touches same-origin /api/ traffic and does three things:
//   1. idempotent requests (GET/HEAD) that hit a gateway error or a transport
//      failure are retried twice with backoff;
//   2. write requests (POST/PUT/PATCH/DELETE) with a replayable body are
//      retried ONCE, but only when the answer proves the request never reached
//      the app server (HTML page or a gateway status without a JSON body).
//      A response from the app itself - JSON of any status, including 409/429
//      and its own 5xx - is never retried, so device commands cannot be
//      duplicated;
//   3. any surviving HTML response is replaced by a small JSON body
//      ({ error, code: 'gateway_unreachable' }) with the original status, so
//      existing clients keep their normal non-JSON handling paths.
//
// Nothing else is intercepted: static files, downloads, range requests and
// every non-/api/ URL are passed through untouched.

(function () {
  'use strict';

  var VERSION = '2';
  if (window.__exrmmNetGuard) return;
  window.__exrmmNetGuard = VERSION;

  var original = window.fetch;
  if (typeof original !== 'function') return;

  // Statuses a gateway/proxy uses when it cannot reach the app server.
  var GATEWAY_STATUS = { 502: 1, 503: 1, 504: 1, 520: 1, 521: 1, 522: 1, 523: 1, 524: 1 };
  var READ_DELAYS = [600, 1600];
  var WRITE_DELAYS = [500];

  function parseUrl(input) {
    try {
      var raw = typeof input === 'string' ? input : (input && input.url) || '';
      return new URL(raw, window.location.href);
    } catch (e) {
      return null;
    }
  }

  function isApiCall(url) {
    return !!url &&
      url.origin === window.location.origin &&
      url.pathname.indexOf('/api/') === 0;
  }

  function requestMethod(input, init) {
    var method = (init && init.method) || (input && input.method) || 'GET';
    return String(method).toUpperCase();
  }

  function wait(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  function htmlTitle(html) {
    var m = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(html || '');
    if (!m) return '';
    return String(m[1]).replace(/\s+/g, ' ').trim();
  }

  function gatewayMessage(status, html, method) {
    var title = htmlTitle(html);
    if (title) title = ' - ' + title;
    var what = (method && method !== 'GET' && method !== 'HEAD')
      ? 'The action did not reach the app server'
      : 'The portal could not be reached through its gateway';
    return what +
      (status ? ' (HTTP ' + status + ')' : '') + title + '. ' +
      'Retry the request; the portal itself is normally up.';
  }

  function asJson(status, statusText, payload) {
    return new Response(JSON.stringify(payload), {
      status: status || 502,
      statusText: statusText || 'Bad Gateway',
      headers: { 'content-type': 'application/json; charset=utf-8' }
    });
  }

  function looksLikeDocument(text) {
    return /^\s*<(!doctype|html|head|body|\?xml)/i.test(String(text || ''));
  }

  function contentType(response) {
    return String((response && response.headers && response.headers.get('content-type')) || '').toLowerCase();
  }

  function isHtmlType(type) {
    return type.indexOf('text/html') !== -1 || type.indexOf('application/xhtml') !== -1;
  }

  function isJsonType(type) {
    return type.indexOf('json') !== -1;
  }

  function discard(response) {
    try {
      if (response && response.body) response.body.cancel();
    } catch (e) { /* already consumed - nothing to release */ }
  }

  // Returns the response callers should see: HTML error pages become JSON.
  function finalize(response, method) {
    var type = contentType(response);
    if (!isHtmlType(type)) return response;
    return response.clone().text().then(function (text) {
      if (!looksLikeDocument(text)) return response;
      try {
        console.warn('[net-guard] gateway returned an HTML page instead of JSON (HTTP ' +
          response.status + (htmlTitle(text) ? ': ' + htmlTitle(text) : '') + ')');
      } catch (e) { /* console unavailable */ }
      return asJson(response.status, response.statusText, {
        error: gatewayMessage(response.status, text, method),
        code: 'gateway_unreachable',
        retryable: true
      });
    }).catch(function () { return response; });
  }

  function transportError(cause, method) {
    var write = method && method !== 'GET' && method !== 'HEAD';
    var err = new Error(write
      ? 'The action did not reach the portal (the connection dropped before an answer arrived). ' +
        'Press the button again - nothing was executed upstream.'
      : 'The portal did not answer (the connection dropped before a response arrived). ' +
        'Press the button again in a moment.');
    err.code = 'network_unreachable';
    err.retryable = true;
    err.cause = cause;
    return err;
  }

  function isAbort(err, init) {
    if (err && err.name === 'AbortError') return true;
    return !!(init && init.signal && init.signal.aborted);
  }

  function offline() {
    try { return typeof navigator !== 'undefined' && navigator.onLine === false; } catch (e) { return false; }
  }

  // The body can only be reused when it is a plain string (all portal calls
  // send JSON text). Request objects and streams cannot be replayed.
  function replayableWrite(input, init, method) {
    if (method === 'GET' || method === 'HEAD') return false;
    if (!init || typeof init !== 'object') return false;
    if (typeof init.body !== 'string') return false;
    if (typeof input !== 'string') return false;
    return true;
  }

  async function guardedFetch(input, init) {
    var url = parseUrl(input);
    if (!isApiCall(url)) return original.call(window, input, init);

    var method = requestMethod(input, init);
    var idempotent = method === 'GET' || method === 'HEAD';
    var canReplay = replayableWrite(input, init, method);
    var delays = offline() ? [] : (idempotent ? READ_DELAYS : (canReplay ? WRITE_DELAYS : []));
    var lastError = null;

    for (var attempt = 0; attempt <= delays.length; attempt++) {
      if (init && init.signal && init.signal.aborted) throw transportError(lastError, method);
      var response = null;
      try {
        response = await original.call(window, input, init);
      } catch (err) {
        if (isAbort(err, init)) throw err;
        response = null;
        lastError = err;
        // A write that threw may already have been processed upstream, so it is
        // never replayed; the caller gets a readable, retryable message instead.
        if (!idempotent) throw transportError(lastError, method);
      }

      if (response) {
        var type = contentType(response);
        // A write is only retried when the answer shows the app never saw it:
        // non-JSON answer plus either a gateway status or an HTML document.
        var transient = idempotent
          ? (GATEWAY_STATUS[response.status] === 1 || isHtmlType(type))
          : (!isJsonType(type) && (GATEWAY_STATUS[response.status] === 1 || isHtmlType(type)));
        if (!transient || attempt === delays.length) return finalize(response, method);
        discard(response);
      } else if (attempt === delays.length) {
        throw transportError(lastError, method);
      }

      await wait(delays[attempt]);
    }

    throw transportError(lastError, method);
  }

  window.fetch = function (input, init) { return guardedFetch(input, init); };
})();
