/**
 * LLM API Validator — CORS proxy as a Cloudflare Pages Function.
 *
 * Route: /api/*  (this file: functions/api/[[path]].js, multipath segment)
 * Thin wrapper: all logic lives in proxy-core.js, shared with worker.js.
 */

import { handleProxy } from '../../proxy-core.js';

export async function onRequest(context) {
  return handleProxy(context.request, context.env || {});
}
