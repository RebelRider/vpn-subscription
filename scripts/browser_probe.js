'use strict';
// Stock browser behavior: no stealth, authentication state, CAPTCHA interaction
// or messages. Only bounded semantic evidence leaves this owned process.
const fs = require('fs');
const crypto = require('crypto');
let browser;
let stopped = false;
const COMPOSER_HINT = /\bask\b|\bmessage\b|\bchatgpt\b|\bquestion\b|what.?s on your mind|спрос|напишите|вопрос/i;
async function stop() {
  if (stopped) return;
  stopped = true;
  if (browser) await browser.close().catch(() => {});
}
for (const name of ['SIGTERM', 'SIGINT']) process.on(name, async () => { await stop(); process.exit(124); });
function compatibleProviders(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.entries(value).some(([key, item]) => {
    if (!item || !key.startsWith('openai') || item.id !== key || !['oauth', 'oidc'].includes(item.type)) return false;
    try {
      const signin = new URL(item.signinUrl), callback = new URL(item.callbackUrl);
      return [signin, callback].every(url => url.protocol === 'https:' && ['chatgpt.com', 'www.chatgpt.com'].includes(url.hostname)) &&
        signin.pathname === '/api/auth/signin/' + key && callback.pathname === '/api/auth/callback/' + key;
    } catch { return false; }
  });
}
function modelCatalog(value) {
  return value && typeof value === 'object' && Array.isArray(value.models) && value.models.length > 0 &&
    value.models.some(item => item && typeof item === 'object' &&
      ((typeof item.slug === 'string' && item.slug.length > 0) || (typeof item.id === 'string' && item.id.length > 0)));
}
async function freshApplicationJson(page, path) {
  // Inspect this exact no-store response, rather than allowing a passive or
  // cached earlier response to satisfy a new measurement round.
  return page.evaluate(async path => {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
    try {
      if (!['/api/auth/providers', '/backend-anon/models'].includes(path)) return null;
      const requested = new URL(path, location.href);
      if (requested.protocol !== 'https:' || !['chatgpt.com', 'www.chatgpt.com'].includes(requested.hostname)
          || requested.username || requested.password || !['', '443'].includes(requested.port)) return null;
      const response = await fetch(requested.href, {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal});
      const actual = new URL(response.url);
      if (actual.origin !== requested.origin || actual.pathname !== requested.pathname || actual.search || actual.hash || response.redirected
          || response.status !== 200 || !(response.headers.get('content-type') || '').toLowerCase().includes('application/json')
          || Number(response.headers.get('content-length') || 0) > 1048576) return null;
      const reader = response.body.getReader(); let total = 0, chunks = [];
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        total += value.length;
        if (total > 1048576) { await reader.cancel(); return null; }
        chunks.push(value);
      }
      const joined = new Uint8Array(total); let position = 0;
      for (const chunk of chunks) { joined.set(chunk, position); position += chunk.length; }
      return JSON.parse(new TextDecoder().decode(joined));
    } catch { return null; } finally { clearTimeout(timer); }
  }, path);
}
async function freshApplicationProof(page) {
  const providers = await freshApplicationJson(page, '/api/auth/providers');
  if (compatibleProviders(providers)) return {passed: true, kind: 'openai-auth-providers'};
  const models = await freshApplicationJson(page, '/backend-anon/models');
  if (modelCatalog(models)) return {passed: true, kind: 'chatgpt-model-catalog'};
  return {passed: false, kind: null};
}
function classify(body, title, status) {
  const text = (title + '\n' + body).toLowerCase();
  if (/unsupported country|unsupported_country|country.{0,30}not supported|not available in your country|region.{0,30}not supported/.test(text)) return 'geographic-restriction';
  if (/just a moment|verify you are human|checking your browser|cf-chl-|cloudflare.{0,50}challenge/.test(text)) return 'cloudflare-challenge-inconclusive';
  if (/captcha|unusual activity|unusual traffic/.test(text)) return 'anti-automation-inconclusive';
  if (/unsupported browser|browser.{0,20}not supported|enable javascript|enable cookies/.test(text)) return 'browser-requirements-inconclusive';
  if (status === 429) return 'rate-limited-inconclusive';
  if (status === 401 || status === 403) return 'access-denied-inconclusive';
  return 'browser-application-proof-missing';
}
function visibleRestriction(text, status) {
  const value = String(text || '').replace(/\s+/g, ' ').toLowerCase();
  if (/unsupported[_ ]country|country.{0,35}(?:not supported|unsupported)|not available in your (?:country|region)|region.{0,25}not supported/.test(value)) return 'geographic-restriction';
  if (/verify (?:that )?you are human|checking your browser|just a moment|complete (?:the )?(?:security|verification) (?:check|challenge)/.test(value)) return 'cloudflare-challenge-inconclusive';
  if (/(?:complete|solve|enter).{0,25}captcha|captcha.{0,25}(?:required|verification)|unusual (?:activity|traffic)/.test(value)) return 'anti-automation-inconclusive';
  if (/too many requests|you are being rate limited|rate limit (?:reached|exceeded)/.test(value) || status === 429) return 'rate-limited-inconclusive';
  if (/(?:log|sign) in (?:or sign up )?to continue|please (?:log|sign) in to (?:continue|use)/.test(value)) return 'authentication-required-inconclusive';
  if (/something went wrong|unable to load chatgpt|application error|an error occurred/.test(value)) return 'browser-visible-application-error-inconclusive';
  if (status === 401 || status === 403) return 'access-denied-inconclusive';
  if (status !== 200) return 'browser-document-http-error-inconclusive';
  return null;
}
function visibleTextSnapshot() {
  // Read rendered text nodes only. Bundles, hidden translations, offscreen
  // accessibility text and transparent elements cannot become blockers.
  if (!document.body) return '';
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const parts = []; let node, visited = 0, total = 0;
  while ((node = walker.nextNode()) && visited++ < 5000 && total < 65536) {
    const parent = node.parentElement;
    if (!parent || !node.textContent.trim() || parent.closest('script,style,noscript,template,[hidden],[aria-hidden="true"]')) continue;
    let visible = true, ancestor = parent, depth = 0;
    while (ancestor && depth++ < 64) {
      const style = getComputedStyle(ancestor);
      if (style.display === 'none' || ['hidden', 'collapse'].includes(style.visibility) || Number(style.opacity) === 0
          || /rect\(0px,?\s*0px,?\s*0px,?\s*0px\)/.test(style.clip) || style.clipPath === 'inset(50%)') { visible = false; break; }
      ancestor = ancestor.parentElement;
    }
    if (!visible) continue;
    const range = document.createRange(); range.selectNodeContents(node);
    const onScreen = [...range.getClientRects()].some(rect => rect.width > 1 && rect.height > 1 && rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth);
    if (!onScreen) continue;
    const text = node.textContent.slice(0, 65536 - total); parts.push(text); total += text.length;
  }
  return parts.join(' ');
}
function mainDocumentResponse(response, page) {
  try {
    const request = response.request();
    if (!request.isNavigationRequest() || request.resourceType() !== 'document' || request.frame() !== page.mainFrame()) return null;
    const status = response.status(), url = response.url();
    return Number.isInteger(status) && status >= 100 && status <= 599 && typeof url === 'string' ? {status, url} : null;
  } catch { return null; }
}
function matchingDocument(document, currentUrl) {
  if (!document) return false;
  try {
    const actual = new URL(document.url), current = new URL(currentUrl);
    return current.protocol === 'https:' && ['chatgpt.com', 'www.chatgpt.com'].includes(current.hostname)
      && ['', '443'].includes(current.port) && !current.username && !current.password && current.pathname === '/'
      && actual.origin === current.origin && actual.pathname === current.pathname && actual.search === current.search;
  } catch { return false; }
}
async function ordinaryGuestNavigation(page) {
  // Only explicit public guest/optional-cookie actions. Never interact with
  // login forms, authentication providers, prompts or challenge widgets.
  const guest = /^(stay logged out|try it now|continue without logging in|continue without (?:an? )?account|continue as guest|не входить|остаться без входа|продолжить без (?:входа|регистрации)|попробовать сейчас|продолжить как гость)$/i;
  const reject = /^(reject all|reject optional|reject optional cookies|decline optional cookies|отклонить все|отклонить необязательные(?: файлы cookie)?)$/i;
  let guestAction = false, cookieAction = false;
  const guestControl = page.getByRole('button', {name: guest}).or(page.getByRole('link', {name: guest})).first();
  await guestControl.waitFor({state: 'visible', timeout: 6000}).catch(() => {});
  if (await guestControl.isVisible().catch(() => false)) {
    const href = await guestControl.getAttribute('href').catch(() => null);
    let allowed = true;
    if (href) {
      try { const destination = new URL(href, page.url()); allowed = destination.protocol === 'https:' && ['chatgpt.com', 'www.chatgpt.com'].includes(destination.hostname); }
      catch { allowed = false; }
    }
    if (allowed) { await guestControl.click({timeout: 5000}); guestAction = true; }
  }
  const rejectControl = page.getByRole('button', {name: reject}).first();
  if (await rejectControl.isVisible().catch(() => false)) { await rejectControl.click({timeout: 3000}); cookieAction = true; }
  return {guest_action: guestAction, rejected_optional_cookies: cookieAction};
}
async function diagnostics(page, status, counters) {
  // Only hashes, public state categories and bounded counts leave the browser.
  // Never return HTML, visible text, cookies, query strings or session material.
  const visible = await page.locator('body').innerText({timeout: 2000}).catch(() => '');
  const title = await page.title().catch(() => '');
  const lower = visible.toLowerCase();
  const counts = await page.evaluate(() => ({
    inputs: document.querySelectorAll('input').length,
    textareas: document.querySelectorAll('textarea').length,
    contenteditables: document.querySelectorAll('[contenteditable="true"]').length,
    plaintext_editors: document.querySelectorAll('[contenteditable="plaintext-only"]').length,
    any_editors: document.querySelectorAll('[contenteditable]').length,
    textbox_roles: document.querySelectorAll('[role="textbox"]').length,
    scripts: document.scripts.length,
    textarea_visible: [...document.querySelectorAll('textarea')].filter(node => node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0 && getComputedStyle(node).visibility !== 'hidden').length,
    textarea_prompt_id: document.querySelectorAll('textarea#prompt-textarea').length,
    textarea_prompt_name: document.querySelectorAll('textarea[name="prompt-textarea"]').length,
    textarea_semantic_placeholder: [...document.querySelectorAll('textarea')].filter(node => /\bask\b|\bmessage\b|\bchatgpt\b|\bquestion\b|what.?s on your mind|спрос|напишите|вопрос/i.test(node.getAttribute('placeholder') || '')).length,
    textarea_semantic_label: [...document.querySelectorAll('textarea')].filter(node => /\bask\b|\bmessage\b|\bchatgpt\b|\bquestion\b|спрос|напишите|вопрос/i.test(node.getAttribute('aria-label') || '')).length,
    textarea_placeholder_present: [...document.querySelectorAll('textarea')].filter(node => Boolean(node.getAttribute('placeholder'))).length,
    textarea_hidden_semantics: document.querySelectorAll('textarea[aria-hidden="true"],textarea[tabindex="-1"]').length,
    textarea_opacity_zero: [...document.querySelectorAll('textarea')].filter(node => Number(getComputedStyle(node).opacity) === 0).length,
    turnstile_fields: document.querySelectorAll('[name="cf-turnstile-response"], [name="g-recaptcha-response"]').length,
    logged_out_actions: [...document.querySelectorAll('button,a')].filter(node => /stay logged out|continue without (?:an? )?account|continue as guest/i.test(node.textContent)).length,
  })).catch(() => ({}));
  let path = '/';
  try { path = new URL(page.url()).pathname; } catch {}
  return {body_sha256: crypto.createHash('sha256').update(visible).digest('hex'),
    title_sha256: crypto.createHash('sha256').update(title).digest('hex'),
    body_characters: visible.length, final_path: path === '/' ? '/' : 'other',
    category: classify(visible.slice(0, 65536), title, status),
    login_gate: /log in to|sign in to|continue with google|create an account/.test(lower),
    application_error: /something went wrong|unable to load|application error|please try again/.test(lower),
    loading: /loading|please wait/.test(lower), ...counts, ...counters};
}
async function main() {
  const raw = fs.readFileSync(process.env.BESTLOCAL_BROWSER_CONFIGURATION, 'utf8');
  if (raw.length > 8192) throw new Error('configuration-limit');
  const config = JSON.parse(raw);
  const playwright = require(process.env.BESTLOCAL_PLAYWRIGHT);
  const args = ['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--window-size=900,700'];
  if (!config.control) args.push('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', '--proxy-bypass-list=<-loopback>');
  const options = {headless: config.headless === true, channel: 'chromium', args, ignoreHTTPSErrors: false,
    acceptDownloads: false, serviceWorkers: 'block', timeout: 20000};
  if (!config.control) options.proxy = {server: 'http://127.0.0.1:' + config.port,
    username: config.username, password: config.password, bypass: '<-loopback>'};
  browser = await playwright.chromium.launchPersistentContext(config.profile, options);
  const page = browser.pages()[0] || await browser.newPage();
  page.setDefaultTimeout(12000);
  const rounds = [];
  for (let index = 0; index < config.rounds; index++) {
    let status = 0, apiProof = false, apiKind = null;
    let document = null, documentSequence = 0;
    const counters = {page_errors: 0, failed_requests: 0, service_json_responses: 0, script_failures: 0, api_observations: [],
      auth_providers_status: 0, anon_models_status: 0, api_models_status: 0};
    const pageError = () => { counters.page_errors = Math.min(1000, counters.page_errors + 1); };
    const requestFailed = request => {
      counters.failed_requests = Math.min(1000, counters.failed_requests + 1);
      if (request.resourceType() === 'script') counters.script_failures = Math.min(1000, counters.script_failures + 1);
    };
    page.on('pageerror', pageError); page.on('requestfailed', requestFailed);
    const tasks = new Set();
    const observe = response => {
      const navigation = mainDocumentResponse(response, page);
      if (navigation) document = {...navigation, sequence: ++documentSequence};
      let url;
      try { url = new URL(response.url()); } catch { return; }
      if (url.protocol !== 'https:' || !['chatgpt.com', 'www.chatgpt.com'].includes(url.hostname)) return;
      if (!/^\/(?:api|backend-anon|backend-api)\//.test(url.pathname)) return;
      const statusName = {'/api/auth/providers': 'auth_providers_status', '/backend-anon/models': 'anon_models_status', '/backend-api/models': 'api_models_status'}[url.pathname];
      if (statusName) counters[statusName] = response.status();
      const path = url.pathname.slice(0, 160).replace(/\b[0-9a-f-]{32,}\b/gi, ':identifier');
      const metadata = {path, status: response.status(), content_type: 'unknown', keys: []};
      if (counters.api_observations.length < 24) counters.api_observations.push(metadata);
      const task = (async () => {
        const headers = await response.allHeaders();
        metadata.content_type = (headers['content-type'] || '').split(';')[0].trim().slice(0, 80);
        if (!(headers['content-type'] || '').includes('application/json') || Number(headers['content-length'] || 0) > 1048576) return;
        const body = await response.body();
        if (body.length > 1048576) return;
        const value = JSON.parse(body.toString());
        counters.service_json_responses += 1;
        if (value && typeof value === 'object' && !Array.isArray(value)) metadata.keys = Object.keys(value).filter(key => /^[A-Za-z_][A-Za-z0-9_-]{0,47}$/.test(key)).slice(0, 24);
      })().catch(() => {});
      tasks.add(task); task.finally(() => tasks.delete(task));
    };
    page.on('response', observe);
    let result;
    try {
      const response = index === 0 ? await page.goto('https://chatgpt.com/', {waitUntil: 'domcontentloaded', timeout: 22000}) :
        await page.reload({waitUntil: 'domcontentloaded', timeout: 22000});
      if (!document) {
        const navigation = mainDocumentResponse(response, page);
        if (navigation) document = {...navigation, sequence: ++documentSequence};
      }
      status = document ? document.status : 0;
      if (index === 0) Object.assign(counters, await ordinaryGuestNavigation(page));
      const knownComposer = page.locator('#prompt-textarea:visible, [data-testid="prompt-textarea"]:visible, textarea[name="prompt-textarea"]:visible, [contenteditable="true"][role="textbox"]:visible, [contenteditable="plaintext-only"][role="textbox"]:visible');
      const semanticComposer = page.getByPlaceholder(COMPOSER_HINT).and(page.locator('textarea:visible'));
      const labeledComposer = page.getByRole('textbox', {name: COMPOSER_HINT}).and(page.locator('textarea:visible'));
      const composer = knownComposer.or(semanticComposer).or(labeledComposer).first();
      // Permit ordinary page JavaScript/redirects to settle. No CAPTCHA is
      // clicked or solved and no browser fingerprint is modified.
      await composer.waitFor({state: 'visible', timeout: 45000}).catch(() => {});
      const rendered = await composer.isVisible().catch(() => false) && await composer.isEnabled().catch(() => false) &&
        await composer.isEditable().catch(() => false) && await composer.evaluate(node => {
          const style = getComputedStyle(node), bounds = node.getBoundingClientRect();
          return node.getAttribute('aria-hidden') !== 'true' && node.getAttribute('tabindex') !== '-1' &&
            Number(style.opacity) > 0 && bounds.width >= 20 && bounds.height >= 10;
        }).catch(() => false);
      // Both reads use ordinary browser cookies/headers generated in this
      // fresh, unauthenticated page. No authentication material is reused.
      const apiDocument = document && document.sequence;
      const freshProof = await freshApplicationProof(page);
      apiProof = freshProof.passed; apiKind = freshProof.kind;
      let timer;
      try { await Promise.race([Promise.allSettled([...tasks]), new Promise(resolve => { timer = setTimeout(resolve, 2000); })]); }
      finally { clearTimeout(timer); }
      let actionable = false;
      if (rendered) {
        try { await composer.click({trial: true, timeout: 3000}); actionable = true; }
        catch {}
      }
      status = document ? document.status : 0;
      const visible = await page.evaluate(visibleTextSnapshot);
      const restriction = visibleRestriction(visible, status);
      const restrictionFree = restriction === null;
      const finalAllowed = matchingDocument(document, page.url());
      const sameDocument = document !== null && document.sequence === apiDocument;
      const passed = rendered && actionable && restrictionFree && apiProof && finalAllowed && sameDocument && status === 200;
      let reason = 'ok';
      if (!passed) {
        reason = restriction || (!finalAllowed ? 'browser-document-proof-missing-inconclusive' :
          !sameDocument ? 'browser-document-changed-inconclusive' :
          rendered && !actionable ? 'browser-composer-not-actionable-inconclusive' : 'browser-application-proof-missing');
        if (rendered && !apiProof && reason === 'browser-application-proof-missing') reason = 'browser-api-proof-missing';
      }
      result = {passed, reason, checked_at: new Date().toISOString(), http_status: status,
        composer: rendered, actionable, restriction_free: restrictionFree, application_json: apiProof, api_kind: apiKind,
        diagnostics: await diagnostics(page, status, counters)};
    } catch (error) {
      const message = String(error && error.message || '');
      result = {passed: false, reason: /ERR_CERT/.test(message) ? 'browser-tls-failed' :
        /ERR_PROXY|ERR_TUNNEL/.test(message) ? 'browser-proxy-failed' :
        /Timeout|timeout/.test(message) ? 'browser-timeout-inconclusive' : 'browser-navigation-failed',
        checked_at: new Date().toISOString(), http_status: status};
    } finally { page.off('response', observe); page.off('pageerror', pageError); page.off('requestfailed', requestFailed); }
    rounds.push(result);
    if (!result.passed) break;
  }
  await stop();
  console.log(JSON.stringify({qualified: rounds.length === config.rounds && rounds.every(item => item.passed), rounds,
    method: 'isolated-browser-composer-and-application-json'}));
}
module.exports = {compatibleProviders, modelCatalog, classify, visibleRestriction, visibleTextSnapshot, mainDocumentResponse, matchingDocument, ordinaryGuestNavigation, freshApplicationJson, freshApplicationProof};
if (require.main === module) main().catch(async () => { await stop(); console.log(JSON.stringify({qualified: false, rounds: [],
  method: 'isolated-browser', reason: 'browser-runtime-failed'})); process.exitCode = 1; });
