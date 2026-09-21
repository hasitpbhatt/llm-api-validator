/**
 * LLM API Validator — Phase-2 CORS proxy (standalone Cloudflare Worker).
 *
 * Thin wrapper: all logic lives in proxy-core.js, shared with the Pages
 * Function (functions/api/[[path]].js) so every fix is written once.
 *
 * Deploy:  npx wrangler deploy   (from this directory)
 */

import { handleProxy } from './proxy-core.js';

export default {
  async fetch(request, env) {
    return handleProxy(request, env);
  }
};
