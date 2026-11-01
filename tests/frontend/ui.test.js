// jsdom tests for vapt_agent/static/index.html -- they execute the REAL page (inline scripts and
// all) against a mocked fetch, so they exercise what a browser would, minus layout/WebGL.
//
//   cd tests/frontend && npm install && npm test          (also run by tests/test_frontend.py)
//
// Covers: the analyst sign-in flow and bearer header on every mutating call, 401 handling, that the
// client no longer sends a `by=` identity, the report download path, and -- regression coverage for
// the stored-XSS fix -- that scanner-derived text and server-supplied identities render inert.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const HTML = fs.readFileSync(path.join(__dirname, '..', '..', 'vapt_agent', 'static', 'index.html'), 'utf8');
const settle = (ms = 25) => new Promise((r) => setTimeout(r, ms));

const MALICIOUS = `<img src=x onerror="window.__xss=true"> it's <b>bold</b> & "quoted"`;

function assessment(overrides = {}) {
  return {
    id: 'asm-1', state: 'planned', created_by: 'alice',
    plan: [{ id: 'step-1', tool: 'nmap', target: '10.10.10.5', preset: 'discovery', kind: 'discovery',
             status: 'proposed', rationale: 'because', origin: 'rules', alternatives_considered: [] }],
    events: [], findings: [], approvals: [], ...overrides,
  };
}

/** Boot the real page. `respond(url, opts)` returns {status, body} (body JSON-encoded, or a
 *  `blob` marker) for each fetch; every call is recorded in `calls`. */
function boot({ respond = () => ({ status: 404, body: {} }), session = {} } = {}) {
  const calls = [], alerts = [], downloads = [];
  const dom = new JSDOM(HTML, {
    runScripts: 'dangerously', url: 'http://localhost/ui/', pretendToBeVisual: true,
    beforeParse(w) {
      w.matchMedia = (q) => ({ matches: false, media: q, addListener() {}, removeListener() {} });
      w.alert = (m) => alerts.push(String(m));
      w.HTMLCanvasElement.prototype.getContext = () => null;       // no WebGL here: hero falls back
      w.URL.createObjectURL = () => 'blob:test';
      w.URL.revokeObjectURL = () => {};
      w.HTMLAnchorElement.prototype.click = function () { downloads.push({ download: this.download, href: this.href }); };
      for (const [k, v] of Object.entries(session)) w.sessionStorage.setItem(k, v);
      w.fetch = async (url, opts = {}) => {
        calls.push({ url, opts });
        const { status = 200, body = {} } = respond(url, opts) || {};
        return { ok: status >= 200 && status < 300, status,
                 json: async () => body, text: async () => JSON.stringify(body), blob: async () => ({ size: 4 }) };
      };
    },
  });
  const w = dom.window;
  const $ = (s) => w.document.querySelector(s);
  return { w, $, calls, alerts, downloads, hdr: (c) => (c.opts.headers || {}).Authorization };
}

const signIn = async (ui, token = 'tok-0123456789abcdef') => {
  ui.$('#tokenInput').value = token;
  ui.$('#signInBtn').click();
  await settle();
};
const whoamiAs = (identity, expected = 'Bearer tok-0123456789abcdef') => (url, opts) =>
  url === '/whoami' ? (opts.headers.Authorization === expected ? { body: { identity } } : { status: 401 }) : null;

// ---------------------------------------------------------------------------------------------

test('starts signed out, with the sign-in card ready', () => {
  const ui = boot();
  assert.equal(ui.$('#authStatus').textContent, 'Not signed in.');
  assert.equal(ui.$('#signOutBtn').hidden, true);
  assert.equal(ui.$('#tokenInput').type, 'password');
  assert.equal(ui.$('#tokenInput').getAttribute('autocomplete'), 'off');
});

test('a mutating call without a token sends no Authorization header and prompts instead of alerting', async () => {
  const ui = boot({ respond: () => ({ status: 401, body: { detail: 'authentication required' } }) });
  ui.$('#createBtn').click();
  await settle();
  assert.equal(ui.calls.length, 1);
  assert.equal(ui.hdr(ui.calls[0]), undefined);
  assert.equal(ui.alerts.length, 0, 'a 401 should guide the user, not pop a raw JSON alert');
  assert.match(ui.$('#authStatus').textContent, /paste a valid analyst token/);
});

test('signing in verifies the token via /whoami, stores it per-tab, and clears the field', async () => {
  const ui = boot({ respond: whoamiAs('alice') });
  await signIn(ui);
  assert.equal(ui.$('#authStatus').textContent, 'Signed in as alice');
  assert.equal(ui.$('#tokenInput').value, '');
  assert.equal(ui.$('#tokenInput').hidden, true);
  assert.equal(ui.$('#signOutBtn').hidden, false);
  assert.equal(ui.w.sessionStorage.getItem('vapt_token'), 'tok-0123456789abcdef');
  assert.equal(ui.w.localStorage.getItem('vapt_token'), null, 'must not persist beyond the tab');
});

test('a rejected token is not stored and the user is told', async () => {
  const ui = boot({ respond: () => ({ status: 401 }) });
  await signIn(ui, 'wrong-token-0123456789');
  assert.equal(ui.$('#authStatus').textContent, 'That token was not accepted.');
  assert.equal(ui.w.sessionStorage.getItem('vapt_token'), null);
  assert.equal(ui.$('#signOutBtn').hidden, true);
});

test('submitting an empty token asks for one without calling the server', async () => {
  const ui = boot();
  ui.$('#signInBtn').click();
  await settle();
  assert.equal(ui.calls.length, 0);
  assert.match(ui.$('#authStatus').textContent, /Paste your analyst token/);
});

test('Enter in the token field signs in', async () => {
  const ui = boot({ respond: whoamiAs('alice') });
  ui.$('#tokenInput').value = 'tok-0123456789abcdef';
  ui.$('#tokenInput').dispatchEvent(new ui.w.KeyboardEvent('keydown', { key: 'Enter' }));
  await settle();
  assert.equal(ui.$('#authStatus').textContent, 'Signed in as alice');
});

test('a token left in sessionStorage is re-verified on load', async () => {
  const ui = boot({ respond: whoamiAs('bob'), session: { vapt_token: 'tok-0123456789abcdef' } });
  await settle();
  assert.equal(ui.$('#authStatus').textContent, 'Signed in as bob');
});

test('a stale stored token is discarded on load', async () => {
  const ui = boot({ respond: () => ({ status: 401 }), session: { vapt_token: 'stale-token-0123456789' } });
  await settle();
  assert.equal(ui.w.sessionStorage.getItem('vapt_token'), null);
  assert.match(ui.$('#authStatus').textContent, /Not signed in/);
});

test('mutating calls carry the bearer token, and the client no longer sends any `by=` identity', async () => {
  const state = { signedIn: false };
  const ui = boot({
    respond: (url, opts) => {
      const w = whoamiAs('alice')(url, opts); if (w) return w;
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/assessments/asm-1') return { body: assessment() };
      return { body: {} };
    },
  });
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#plan button').click();                       // "Approve & run" on the proposed step
  await settle();

  const posts = ui.calls.filter((c) => c.opts.method === 'POST');
  assert.ok(posts.length >= 3, `expected create + decision + run, saw ${posts.map((p) => p.url)}`);
  for (const c of posts) assert.equal(ui.hdr(c), 'Bearer tok-0123456789abcdef', c.url);
  for (const c of ui.calls) assert.ok(!/[?&]by=/.test(c.url), `client must not name the actor: ${c.url}`);
  assert.ok(posts.some((c) => c.url === '/assessments/asm-1/plan/step-1/decision?approved=true'));
  assert.match(ui.$('#assessmentMeta').textContent, /opened by alice/);
  void state;
});

test('denying an approval sends no `by=` and carries the token', async () => {
  const withApproval = assessment({
    findings: [{ id: 'f1', title: 't', asset: 'a', severity: 'low', status: 'suspected', validation_status: 'not_validated',
                 source_tools: ['nmap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [] }],
    approvals: [{ id: 'appr-1', action: 'validate', state: 'pending', outcome: '',
                  requested_by: 'alice', decided_by: '', executed_by: '' }],
  });
  const ui = boot({
    respond: (url, opts) => whoamiAs('bob')(url, opts) ||
      (url === '/assessments' ? { body: withApproval } : { body: withApproval }),
  });
  ui.w.prompt = () => 'not in scope window';
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  assert.match(ui.$('#approvals').textContent, /requested_by=alice/);
  ui.$('#approvals button.ghost').click();             // Deny
  await settle();
  const decision = ui.calls.find((c) => /approvals\/appr-1\/decision/.test(c.url));
  assert.ok(decision, 'decision call made');
  assert.ok(!/by=/.test(decision.url), decision.url);
  assert.match(decision.url, /approved=false&reason=not%20in%20scope%20window/);
  assert.equal(ui.hdr(decision), 'Bearer tok-0123456789abcdef');
});

test('report generation POSTs with the token and downloads the PDF (window.open can do neither)', async () => {
  const ui = boot({
    respond: (url, opts) => whoamiAs('alice')(url, opts) ||
      (url === '/assessments' ? { body: assessment() } : { body: {} }),
  });
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#reportBtn').click();
  await settle();
  const call = ui.calls.find((c) => c.url === '/assessments/asm-1/report');
  assert.ok(call, 'report endpoint called');
  assert.equal(call.opts.method, 'POST');
  assert.equal(ui.hdr(call), 'Bearer tok-0123456789abcdef');
  assert.deepEqual(ui.downloads.map((d) => d.download), ['VAPT-asm-1.pdf']);
});

test('uploads carry the token but leave Content-Type to the browser (multipart boundary)', async () => {
  const ui = boot({
    respond: (url, opts) => whoamiAs('alice')(url, opts) ||
      (url === '/assessments' ? { body: assessment() } : { body: assessment() }),
  });
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  Object.defineProperty(ui.$('#importFile'), 'files', { value: [new ui.w.File(['<x/>'], 'a.nessus')] });
  ui.$('#importBtn').click();
  await settle();
  const up = ui.calls.find((c) => c.url === '/assessments/asm-1/import/nessus');
  assert.ok(up);
  assert.equal(ui.hdr(up), 'Bearer tok-0123456789abcdef');
  assert.equal((up.opts.headers || {})['Content-Type'], undefined);
  assert.ok(up.opts.body instanceof ui.w.FormData);
});

test('a 401 mid-session (e.g. the server restarted with new tokens) signs the user out cleanly', async () => {
  let reject = false;
  const ui = boot({
    respond: (url, opts) => whoamiAs('alice')(url, opts) ||
      (reject ? { status: 401 } : { body: assessment() }),
  });
  await signIn(ui);
  reject = true;
  ui.$('#createBtn').click();
  await settle();
  assert.equal(ui.w.sessionStorage.getItem('vapt_token'), null);
  assert.match(ui.$('#authStatus').textContent, /Not signed in/);
  assert.equal(ui.alerts.length, 0);
});

test('signing out forgets the token: the next call is anonymous', async () => {
  const ui = boot({ respond: (url, opts) => whoamiAs('alice')(url, opts) || { status: 401 } });
  await signIn(ui);
  ui.$('#signOutBtn').click();
  assert.equal(ui.w.sessionStorage.getItem('vapt_token'), null);
  assert.equal(ui.$('#authStatus').textContent, 'Signed out.');
  ui.$('#createBtn').click();
  await settle();
  assert.equal(ui.hdr(ui.calls.at(-1)), undefined);
});

// ---- rendering safety (regression coverage for the stored-XSS fix) ------------------------------

test('scanner-derived text and server-supplied identities render as inert text, never markup', async () => {
  const hostile = assessment({
    created_by: MALICIOUS,
    plan: [{ id: 'step-1', tool: 'nmap', target: '10.10.10.5', preset: 'discovery', kind: 'discovery',
             status: 'proposed', rationale: MALICIOUS, origin: 'rules', alternatives_considered: [] }],
    events: [{ level: 'decision', ts: '2026-01-01T00:00:00+00:00', message: MALICIOUS }],
    findings: [{ id: 'raw-1', title: MALICIOUS, asset: MALICIOUS, port: 80, severity: 'critical', priority: 'P1',
                 status: 'suspected', validation_status: 'not_validated', confidence: 0.9, risk_score: 80,
                 source_tools: ['nikto'], cve: [MALICIOUS], cwe: [], owasp: [], mitre_attack: [MALICIOUS], merged_from: [] }],
    approvals: [{ id: 'appr-1', action: MALICIOUS, state: 'pending', outcome: MALICIOUS,
                  requested_by: MALICIOUS, decided_by: MALICIOUS, executed_by: MALICIOUS }],
  });
  const ui = boot({ respond: (url, opts) => whoamiAs(MALICIOUS)(url, opts) || { body: hostile } });
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();

  assert.equal(ui.w.__xss, undefined, 'injected handler must never run');
  for (const id of ['#assessmentMeta', '#plan', '#events', '#findings', '#approvals', '#authStatus']) {
    assert.equal(ui.$(id).querySelector('img'), null, `${id} contains a live <img>`);
    // (the app uses its own <b> for ids/titles, so look for the payload's <b>bold</b> specifically)
    const injected = [...ui.$(id).querySelectorAll('b')].filter((b) => b.textContent === 'bold');
    assert.equal(injected.length, 0, `${id} rendered the payload's <b> as live markup`);
  }
  for (const id of ['#plan', '#events', '#findings', '#approvals']) {
    assert.ok(ui.$(id).textContent.includes('<img src=x'), `${id} should show the payload as visible text`);
  }
  assert.ok(ui.$('#authStatus').textContent.includes('<img src=x'));
  // the only values spliced into inline onclick attributes are server-generated ids
  assert.match(ui.$('#findings').innerHTML, /onclick="requestApproval\('raw-1'\)"/);
});

test('the approval request button passes only the finding id, never scanner text', async () => {
  const f = { id: 'raw-1', title: `it's "bad"`, asset: '10.10.10.5', severity: 'high', priority: 'P2',
              status: 'suspected', validation_status: 'not_validated', confidence: 0.5, risk_score: 50,
              source_tools: ['zap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [] };
  const ui = boot({
    respond: (url, opts) => whoamiAs('alice')(url, opts) ||
      (opts.method === 'POST' && /\/approvals$/.test(url) ? { body: {} } : { body: assessment({ findings: [f] }) }),
  });
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#findings button.ghost').click();
  await settle();
  const req = ui.calls.find((c) => /\/approvals$/.test(c.url));
  assert.ok(req, 'approval request sent despite quotes in the title');
  const body = JSON.parse(req.opts.body);
  assert.equal(body.finding_id, 'raw-1');
  assert.equal(body.action, `Human-approved check-mode validation of it's "bad" on 10.10.10.5`);
});

// ---- motion system ------------------------------------------------------------------------------

test('static app buttons are bound for motion at load (the motion script runs before #app exists)', () => {
  const ui = boot();
  for (const sel of ['#createBtn', '#signInBtn', '#importBtn', '#analyseBtn', '#reportBtn']) {
    assert.equal(ui.$(sel).dataset.fxBound, '1', `${sel} not bound`);
  }
});
