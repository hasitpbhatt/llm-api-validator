/**
 * LLM API Validator — shared proxy core.
 *
 * Imported by BOTH entry points so there is a single implementation:
 *   - worker.js                  (standalone Cloudflare Worker)
 *   - functions/api/[[path]].js  (Cloudflare Pages Function, same-origin /api)
 *
 * Contract (BYOK — the proxy never stores anything):
 *   GET/POST /api/<path>?target=<api-base-url>
 *   Header:  X-User-Token: <user's bearer token>   (or Authorization / x-api-key)
 *
 * Env vars ([vars] / Pages environment variables):
 *   DEFAULT_TARGET   — fallback when ?target= is missing
 *   ALLOWED_TARGETS  — comma-separated hostnames or URLs. When SET, anything
 *                      other than those hosts (or their subdomains) gets 403.
 *                      Exact-host matching — never string-prefix (prefix checks
 *                      are bypassable, e.g. https://api.openai.com.evil.com).
 *
 * Security stance:
 *   - BYOK only: there is deliberately no server-side API_KEY fallback. With
 *     Access-Control-Allow-Origin:* a server-held key would be stealable by
 *     any website that POSTs here without a token.
 *   - Targets may be any public host (that's the product: validate your own
 *     endpoint), but loopback/private/metadata hosts are always refused so the
 *     Worker can't be used as a probe for internal networks.
 *   - Upstream Content-Type is only passed through for JSON / event-stream;
 *     anything else (especially HTML) is downgraded to octet-stream with
 *     nosniff + CSP so a crafted ?target= can never execute script on this
 *     origin.
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
    'Access-Control-Allow-Methods': 'GET, POST, HEAD, OPTIONS',
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

function isBlockedHost(hostname) {
  var h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || /\.(local|internal|localdomain|lan|home|corp)$/.test(h)) return true;
  var v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    var a = +v4[1], b = +v4[2];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;          // cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true;          // private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true;                        // multicast/reserved
    return false;
  }
  if (h.charAt(0) === '[') {
    var inner = h.slice(1, h.indexOf(']'));
    if (/^(::1?$|f[cd]|fe80)/i.test(inner)) return true;
    var embedded = /:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(inner);
    if (embedded && isBlockedHost(embedded[1])) return true;
  }
  return false;
}

function hostAllowed(parsed, env) {
  if (!env.ALLOWED_TARGETS) return true; // BYOK: user's token, user's endpoint
  var want = parsed.hostname.toLowerCase();
  var allowed = String(env.ALLOWED_TARGETS).split(',')
    .map(function (s) { return s.trim(); }).filter(Boolean);
  return allowed.some(function (entry) {
    var host;
    try {
      host = (entry.indexOf('://') === -1 ? new URL('https://' + entry) : new URL(entry)).hostname.toLowerCase();
    } catch (e) { return false; }
    return want === host || want.endsWith('.' + host);
  });
}

var SAFE_UPSTREAM_CT = /^application\/([\w.+-]+\+)?json|^text\/event-stream/i;

export async function handleProxy(request, env) {
  env = env || {};
  var url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }
  if (request.method !== 'GET' && request.method !== 'POST' && request.method !== 'HEAD') {
    return fail('Method not allowed', 405, request);
  }

  if (!url.pathname.startsWith('/api/') && url.pathname !== '/api') {
    return fail('LLM API proxy — use /api/<path>?target=<api-base-url>', 404, request);
  }

  // ── Resolve and validate target ──
  var target = ((url.searchParams.get('target') || env.DEFAULT_TARGET || '') + '').replace(/\/+$/, '');
  if (!target) {
    return fail('Missing ?target=<api-base-url>', 400, request);
  }
  var parsed;
  try { parsed = new URL(target); } catch (e) { parsed = null; }
  if (!parsed || (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')) {
    return fail('Invalid ?target=<api-base-url> (must be http(s))', 400, request);
  }
  if (isBlockedHost(parsed.hostname)) return fail('Target host not allowed', 403, request);
  if (!hostAllowed(parsed, env)) return fail('Target not in ALLOWED_TARGETS', 403, request);

  // ── Upstream URL: /api<rest> + remaining query (minus target) ──
  var rest = url.pathname.slice('/api'.length) || '/';
  var qs = new URLSearchParams(url.searchParams);
  qs.delete('target');
  var upstream = target + rest + (qs.toString() ? '?' + qs.toString() : '');

  // ── Auth: prefer an already-provided header, else build from X-User-Token ──
  var isAnthropic = /anthropic/i.test(target);
  var headers = new Headers();
  var ct = request.headers.get('content-type');
  if (ct) headers.set('Content-Type', ct);
  var accept = request.headers.get('accept');
  if (accept) headers.set('Accept', accept);

  var incomingAuth = request.headers.get('authorization');
  var incomingKey = request.headers.get('x-api-key');
  var token = (request.headers.get('X-User-Token') || '').trim();
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
  var outCt = upstreamRes.headers.get('content-type') || '';
  // Never let upstream pick a scriptable type on this origin.
  out.set('Content-Type', SAFE_UPSTREAM_CT.test(outCt) ? outCt : 'application/octet-stream');
  out.set('X-Content-Type-Options', 'nosniff');
  out.set('Content-Security-Policy', "default-src 'none'");
  // Streaming bodies pass straight through untouched.
  return new Response(upstreamRes.body, { status: upstreamRes.status, headers: out });
}
