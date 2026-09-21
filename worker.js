/**
 * LLM API Validator — Phase-2 CORS proxy (Cloudflare Worker).
 *
 * Why this exists: browsers block cross-origin fetch() to LLM APIs that don't
 * send `Access-Control-Allow-Origin`. A Worker is server-side, so CORS doesn't
 * apply to its outbound fetch. It just forwards and streams back.
 *
 * Contract (per request — no token is ever stored):
 *   GET/POST https://<worker>/api/<path>?target=<api-base-url>
 *   Header:  X-User-Token: <user's bearer token>
 *
 * Examples:
 *   GET  /api/v1/models?target=https://api.openai.com/v1
 *   POST /api/v1/chat/completions?target=https://api.openai.com/v1
 *
 * Optional env vars (wrangler.toml [vars]):
 *   DEFAULT_TARGET  — fallback when ?target= is missing
 *   API_KEY         — server-side key used only if the request has no X-User-Token
 *   ALLOWED_TARGETS — comma-separated URL prefixes; requests to other targets get 403
 *
 * Deploy:  npx wrangler deploy   (from this directory)
 */

function corsHeaders(request) {
  var requested =
    (request.headers.get('Access-Control-Request-Headers') ||
      'Content-Type, Authorization, X-User-Token, x-api-key, anthropic-version, anthropic-beta, anthropic-dangerous-direct-browser-access')
      .split(',')
      .map(function (h) { return h.trim(); })
      .filter(Boolean)
      .join(', ');
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': requested,
    'Access-Control-Max-Age': '86400'
  };
}

function fail(message, status, request) {
  return new Response(JSON.stringify({ error: message }), {
    status: status,
    headers: Object.assign({ 'Content-Type': 'application/json' }, corsHeaders(request))
  });
}

export default {
  async fetch(request, env) {
    var url = new URL(request.url);

    // Preflight — browsers send this before POSTs with auth headers.
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (!url.pathname.startsWith('/api/')) {
      return fail('LLM API proxy — use /api/<path>?target=<api-base-url>', 404, request);
    }

    // ── Resolve target ──
    var target = (url.searchParams.get('target') || (env.DEFAULT_TARGET || '')).replace(/\/+$/, '');
    if (!target || !/^https?:\/\//i.test(target)) {
      return fail('Missing or invalid ?target=<api-base-url> (must be http(s))', 400, request);
    }
    if (env.ALLOWED_TARGETS) {
      var allowed = env.ALLOWED_TARGETS.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      var ok = allowed.some(function (prefix) { return target.indexOf(prefix) === 0; });
      if (!ok) return fail('Target not in ALLOWED_TARGETS', 403, request);
    }

    // ── Upstream URL: /api<rest> + remaining query (minus target) ──
    var rest = url.pathname.slice('/api'.length) || '/';
    var qs = new URLSearchParams(url.searchParams);
    qs.delete('target');
    var upstream = target + rest + (qs.toString() ? '?' + qs.toString() : '');

    // ── Auth: prefer an already-provided Authorization, else build from token ──
    var isAnthropic = /anthropic/i.test(target);
    var headers = new Headers();
    var ct = request.headers.get('content-type');
    if (ct) headers.set('Content-Type', ct);
    var accept = request.headers.get('accept');
    if (accept) headers.set('Accept', accept);

    var incomingAuth = request.headers.get('authorization');
    var incomingKey = request.headers.get('x-api-key');
    var token = request.headers.get('X-User-Token') || env.API_KEY || '';
    if (incomingAuth) {
      headers.set('Authorization', incomingAuth);
    } else if (incomingKey) {
      headers.set('x-api-key', incomingKey);
    } else if (token) {
      if (isAnthropic) headers.set('x-api-key', token);
      else headers.set('Authorization', 'Bearer ' + token);
    }

    // Anthropic requires a version header server-side.
    var av = request.headers.get('anthropic-version');
    if (isAnthropic) headers.set('anthropic-version', av || '2023-06-01');
    var beta = request.headers.get('anthropic-beta');
    if (beta) headers.set('anthropic-beta', beta);

    // NOTE: never log the token. Upstream errors forward the status + body.
    var upstreamRes;
    try {
      upstreamRes = await fetch(upstream, {
        method: request.method,
        headers: headers,
        body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body
      });
    } catch (e) {
      return fail('Upstream fetch failed: ' + (e.message || e), 502, request);
    }

    var out = new Headers(corsHeaders(request));
    var outCt = upstreamRes.headers.get('content-type');
    if (outCt) out.set('Content-Type', outCt);
    // Streaming bodies pass straight through untouched.
    return new Response(upstreamRes.body, { status: upstreamRes.status, headers: out });
  }
};
