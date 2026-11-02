// jsdom tests for vapt_agent/static/index.html -- they execute the REAL page (inline scripts and
// all) against a mocked fetch, so they exercise what a browser would, minus layout/WebGL and real
// HTTP cookie mechanics (those are covered by tests/test_api_auth.py's TestClient suite, which
// does exercise real Set-Cookie/Cookie semantics). What this suite covers instead: that the page's
// own JS correctly implements the CSRF-token-echo contract, role-gated UI, the must-change-password
// flow, the admin panel, and -- still critical -- that scanner-derived text and server-supplied
// identities render as inert text, never markup.
//
//   cd tests/frontend && npm install && npm test          (also run by tests/test_frontend.py)
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const HTML = fs.readFileSync(path.join(__dirname, '..', '..', 'vapt_agent', 'static', 'index.html'), 'utf8');
const settle = (ms = 25) => new Promise((r) => setTimeout(r, ms));

const MALICIOUS = `<img src=x onerror="window.__xss=true"> it's <b>bold</b> & "quoted"`;
const CSRF = 'csrf-token-abc123';

function whoami(username, role, must_change_password = false) {
  return { username, role, must_change_password, csrf_token: CSRF };
}

function assessment(overrides = {}) {
  return {
    id: 'asm-1', state: 'planned', created_by: 'alice',
    plan: [{ id: 'step-1', tool: 'nmap', target: '10.10.10.5', preset: 'discovery', kind: 'discovery',
             status: 'proposed', rationale: 'because', origin: 'rules', alternatives_considered: [] }],
    events: [], findings: [], approvals: [], ...overrides,
  };
}

/** Boot the real page. `respond(url, opts)` returns {status, body} for each fetch; every call is
 *  recorded in `calls`. By default GET /whoami -> 401 (signed out), matching a fresh page load. */
function boot({ respond, signedInAs = null } = {}) {
  const calls = [], alerts = [], downloads = [], eventSources = [];
  const defaultRespond = (url, opts) => {
    if (url === '/whoami') {
      return signedInAs ? { body: whoami(signedInAs.username, signedInAs.role, signedInAs.must_change_password) }
                        : { status: 401, body: { detail: 'authentication required' } };
    }
    return { status: 404, body: {} };
  };
  const dom = new JSDOM(HTML, {
    runScripts: 'dangerously', url: 'http://localhost/ui/', pretendToBeVisual: true,
    beforeParse(w) {
      w.matchMedia = (q) => ({ matches: false, media: q, addListener() {}, removeListener() {} });
      w.alert = (m) => alerts.push(String(m));
      w.HTMLCanvasElement.prototype.getContext = () => null;
      w.URL.createObjectURL = () => 'blob:test';
      w.URL.revokeObjectURL = () => {};
      w.HTMLAnchorElement.prototype.click = function () { downloads.push({ download: this.download }); };
      // jsdom has no real EventSource -- a minimal stand-in so openEventStream()/closeEventStream()
      // (CA-1) exercise their real logic; tests drive it by calling .onmessage(...) themselves.
      w.EventSource = class {
        constructor(url) { this.url = url; this.onmessage = null; this.closed = false; eventSources.push(this); }
        close() { this.closed = true; }
      };
      w.fetch = async (url, opts = {}) => {
        calls.push({ url, opts });
        const r = (respond && respond(url, opts)) ?? defaultRespond(url, opts);
        const { status = 200, body = {} } = r || {};
        return { ok: status >= 200 && status < 300, status,
                 headers: { get: (h) => (r && r.headers && r.headers[h.toLowerCase()]) || null },
                 json: async () => body, text: async () => JSON.stringify(body), blob: async () => ({ size: 4 }) };
      };
    },
  });
  const w = dom.window;
  const $ = (s) => w.document.querySelector(s);
  return { w, $, calls, alerts, downloads, eventSources, csrfOf: (c) => (c.opts.headers || {})['X-CSRF-Token'] };
}

async function signIn(ui, username = 'alice', password = 'correct-horse-1') {
  ui.$('#loginUsername').value = username;
  ui.$('#loginPassword').value = password;
  ui.$('#signInBtn').click();
  await settle();
}

// ---------------------------------------------------------------------------------------------

test('a fresh page checks /whoami and starts signed out with the app hidden', async () => {
  const ui = boot();
  await settle();
  assert.equal(ui.$('#authCard').hidden, false);
  assert.equal(ui.$('#mainApp').hidden, true);
  assert.equal(ui.$('#signedInBar').hidden, true);
  assert.ok(ui.calls.some((c) => c.url === '/whoami'));
});

test('a returning session (valid cookie) is restored from /whoami alone, no form needed', async () => {
  const ui = boot({ signedInAs: { username: 'alice', role: 'analyst' } });
  await settle();
  assert.equal(ui.$('#authCard').hidden, true);
  assert.equal(ui.$('#mainApp').hidden, false);
  assert.match(ui.$('#whoami').textContent, /alice \(analyst\)/);
});

test('the activity log is an ARIA live region (PL-1), announced to screen readers as it updates', async () => {
  const ui = boot();
  await settle();
  const events = ui.$('#events');
  assert.equal(events.getAttribute('aria-live'), 'polite');
  assert.equal(events.getAttribute('role'), 'log');
});

test('submitting without both fields does not call the server', async () => {
  const ui = boot();
  await settle();
  ui.$('#signInBtn').click();
  await settle();
  assert.ok(!ui.calls.some((c) => c.url === '/login'));
  assert.match(ui.$('#authStatus').textContent, /Enter a username and password/);
});

test('successful login reveals the app and stores nothing in any browser storage', async () => {
  const ui = boot({
    respond: (url, opts) => url === '/login' ? { body: whoami('alice', 'analyst') } : null,
  });
  await settle();
  await signIn(ui);
  assert.equal(ui.$('#mainApp').hidden, false);
  assert.equal(ui.$('#authCard').hidden, true);
  assert.equal(ui.$('#loginPassword').value, '');
  assert.equal(ui.w.localStorage.length, 0);
  assert.equal(ui.w.sessionStorage.length, 0);     // the session lives only in the HttpOnly cookie
});

test('wrong credentials show a generic message and the login call carries no CSRF header', async () => {
  const ui = boot({ respond: (url) => url === '/login' ? { status: 401, body: { detail: 'invalid username or password' } } : null });
  await settle();
  await signIn(ui, 'alice', 'wrong');
  assert.match(ui.$('#authStatus').textContent, /Incorrect username or password/);
  const loginCall = ui.calls.find((c) => c.url === '/login');
  assert.equal(ui.csrfOf(loginCall), undefined);
  assert.equal(ui.$('#mainApp').hidden, true);
});

test('423 (locked) and 429 (rate limited) show their own messages', async () => {
  const ui = boot({ respond: (url) => url === '/login' ? { status: 423, body: { detail: 'account temporarily locked; retry after 30s' } } : null });
  await settle();
  await signIn(ui);
  assert.match(ui.$('#authStatus').textContent, /locked/);

  const ui2 = boot({ respond: (url) => url === '/login' ? { status: 429, body: {} } : null });
  await settle();
  await signIn(ui2);
  assert.match(ui2.$('#authStatus').textContent, /Too many attempts/);
});

test('must_change_password hides everything else and shows only the change-password form', async () => {
  const ui = boot({ respond: (url) => url === '/login' ? { body: whoami('dave', 'analyst', true) } : null });
  await settle();
  await signIn(ui, 'dave');
  assert.equal(ui.$('#pwChangeCard').hidden, false);
  assert.equal(ui.$('#mainApp').hidden, true);
  assert.equal(ui.$('#signedInBar').hidden, true);
  assert.equal(ui.$('#adminCard').hidden, true);
  assert.match(ui.$('#pwChangeReason').textContent, /dave/);
});

test('change-password mismatch is caught client-side without a server call', async () => {
  const ui = boot({ respond: (url) => url === '/login' ? { body: whoami('dave', 'analyst', true) } : null });
  await settle();
  await signIn(ui, 'dave');
  ui.$('#pwCurrent').value = 'old-password-123';
  ui.$('#pwNew').value = 'new-password-123';
  ui.$('#pwNewConfirm').value = 'different-123';
  ui.$('#pwChangeBtn').click();
  await settle();
  assert.match(ui.$('#pwChangeStatus').textContent, /do not match/);
  assert.ok(!ui.calls.some((c) => c.url === '/change-password'));
});

test('successful change-password re-fetches whoami and reveals the app', async () => {
  let changed = false;
  const ui = boot({
    respond: (url) => {
      if (url === '/login') return { body: whoami('dave', 'analyst', true) };
      if (url === '/change-password') { changed = true; return { body: { ok: true } }; }
      if (url === '/whoami' && changed) return { body: whoami('dave', 'analyst', false) };
      return null;
    },
  });
  await settle();
  await signIn(ui, 'dave');
  ui.$('#pwCurrent').value = 'old-password-123';
  ui.$('#pwNew').value = 'new-strong-password-1';
  ui.$('#pwNewConfirm').value = 'new-strong-password-1';
  ui.$('#pwChangeBtn').click();
  await settle();
  const pwCall = ui.calls.find((c) => c.url === '/change-password');
  assert.equal(ui.csrfOf(pwCall), CSRF);
  assert.equal(ui.$('#mainApp').hidden, false);
  assert.equal(ui.$('#pwChangeCard').hidden, true);
});

test('"Start assessment" shows a busy state while the request is in flight, then clears it', async () => {
  const ui = boot({
    respond: (url) => (url === '/login') ? { body: whoami('alice', 'analyst') } : { body: assessment() },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  assert.equal(ui.$('#createBtn').disabled, true, 'disabled synchronously on click, before the response lands');
  assert.ok(ui.$('#createBtn').classList.contains('is-busy'));
  await settle();
  assert.equal(ui.$('#createBtn').disabled, false, 're-enabled once the request settles');
  assert.ok(!ui.$('#createBtn').classList.contains('is-busy'));
});

test('scope inputs are saved to localStorage on submit and restored on the next page load (PL-3)', async () => {
  const ui1 = boot({
    respond: (url) => (url === '/login') ? { body: whoami('alice', 'analyst') } : { body: assessment() },
  });
  await settle();
  await signIn(ui1);
  ui1.$('#request').value = 'Assess the staging web tier before the demo.';
  ui1.$('#targets').value = '10.10.10.9, app2.lab.local';
  ui1.$('#exclusions').value = '10.10.10.9:3389';
  ui1.$('#allowActive').checked = true;
  ui1.$('#createBtn').click();
  await settle();
  const saved = JSON.parse(ui1.w.localStorage.getItem('vapt_scope_inputs_v1'));
  assert.equal(saved.targets, '10.10.10.9, app2.lab.local');
  assert.equal(saved.allowActive, true);

  // A fresh boot is a fresh jsdom window with its own localStorage -- carry the saved value over,
  // exactly as a real browser would across a reload of the same origin.
  const ui2 = boot({ respond: (url) => (url === '/login') ? { body: whoami('alice', 'analyst') } : null });
  ui2.w.localStorage.setItem('vapt_scope_inputs_v1', JSON.stringify(saved));
  // The inline script already ran during JSDOM parsing (before this line), so re-run the restore
  // explicitly to exercise it against the now-populated localStorage, exactly as page load does.
  ui2.w.restoreScopeInputs();
  assert.equal(ui2.$('#targets').value, '10.10.10.9, app2.lab.local');
  assert.equal(ui2.$('#exclusions').value, '10.10.10.9:3389');
  assert.equal(ui2.$('#allowActive').checked, true);
});

test('mutating calls echo X-CSRF-Token from /whoami or /login, and credentials are same-origin', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/assessments/asm-1') return { body: assessment() };
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#plan button').click();                 // "Approve & run"
  await settle();

  const posts = ui.calls.filter((c) => c.opts.method === 'POST' && c.url !== '/login');
  assert.ok(posts.length >= 2, posts.map((p) => p.url).join(', '));
  for (const c of posts) {
    assert.equal(ui.csrfOf(c), CSRF, c.url);
    assert.equal(c.opts.credentials, 'same-origin', c.url);
  }
  const loginCall = ui.calls.find((c) => c.url === '/login');
  assert.equal(ui.csrfOf(loginCall), undefined, 'no session exists yet when logging in');
});

test('"Load audit trail" fetches the scoped audit log and renders the chain verdict', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/audit?assessment_id=asm-1') {
        return { body: { ok: true, message: '3 entries, chain intact', entries: [
          { seq: 1, ts: '2024-01-01T00:00:00', actor: 'alice', action: 'assessment.create',
            details: { assessment: 'asm-1', targets: ['10.10.10.5'] } },
        ] } };
      }
      return { body: assessment() };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#auditBtn').click();
  await settle();

  assert.ok(ui.calls.some((c) => c.url === '/audit?assessment_id=asm-1'));
  const html = ui.$('#auditResult').innerHTML;
  assert.match(html, /chain intact/);
  assert.match(html, /assessment\.create/);
  assert.match(html, /alice/);
});

test('"Load audit trail" shows a chain-broken verdict distinctly', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/audit?assessment_id=asm-1') {
        return { body: { ok: false, message: 'chain broken at seq 2', entries: [] } };
      }
      return { body: assessment() };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#auditBtn').click();
  await settle();

  assert.match(ui.$('#auditResult').innerHTML, /chain broken/);
});

test('"Compare" fetches the diff endpoint and renders new/fixed/persisting', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/assessments/asm-1/diff/asm-0') {
        return { body: {
          before_id: 'asm-0', after_id: 'asm-1',
          new: [{ title: 'New SQLi', asset: '10.10.10.5', port: 80, severity: 'high' }],
          fixed: [{ title: 'Old XSS', asset: '10.10.10.5', port: 443, severity: 'medium' }],
          persisting: [],
        } };
      }
      return { body: assessment() };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#diffAgainst').value = 'asm-0';
  ui.$('#diffBtn').click();
  await settle();

  assert.ok(ui.calls.some((c) => c.url === '/assessments/asm-1/diff/asm-0'));
  const html = ui.$('#diffResult').innerHTML;
  assert.match(html, /New SQLi/);
  assert.match(html, /Old XSS/);
  assert.match(html, /1 new/);
  assert.match(html, /1 fixed/);
});

test('"Compare" without an earlier assessment ID shows a toast, not a server call', async () => {
  const ui = boot({
    respond: (url, opts) => (url === '/login') ? { body: whoami('alice', 'analyst') }
                           : (url === '/assessments' && opts.method === 'POST') ? { body: assessment() }
                           : { body: assessment() },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#diffBtn').click();
  await settle();

  assert.ok(!ui.calls.some((c) => c.url.includes('/diff/')));
  assert.ok(ui.$('#toastStack .toast'), 'a toast asked for the earlier assessment ID');
});

test('"Approve & run" starts a background scan and polls it to completion', async () => {
  let getCount = 0;
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/assessments/asm-1/plan/step-1/decision') return { body: {} };
      if (url === '/assessments/asm-1/plan/step-1/run') return { body: { id: 'run-1', status: 'running' } };
      if (url === '/assessments/asm-1/runs/run-1') return { body: { id: 'run-1', status: 'ok' } };
      if (url === '/assessments/asm-1') {
        getCount++;                 // first refresh (right after 'run') shows 'running', then 'done'
        return { body: assessment({ plan: [{ ...assessment().plan[0], status: getCount === 1 ? 'running' : 'done' }] }) };
      }
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#plan button').click();                 // "Approve & run"
  await settle(80);

  assert.ok(ui.calls.some((c) => c.url === '/assessments/asm-1/plan/step-1/run'));
  assert.ok(ui.calls.some((c) => c.url === '/assessments/asm-1/runs/run-1'), 'polled the run status endpoint');
  assert.ok(ui.$('#plan').innerHTML.includes('>done<'), 'final refresh shows the completed state');
});

test('a 401 mid-session returns to the sign-in form and clears the current assessment', async () => {
  let reject = false;
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (reject) return { status: 401, body: { detail: 'authentication required' } };
      return { body: assessment() };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  reject = true;
  ui.$('#analyseBtn').click();
  await settle();
  assert.equal(ui.$('#authCard').hidden, false);
  assert.equal(ui.$('#mainApp').hidden, true);
  assert.equal(ui.alerts.length, 0);
});

test('a 403 with the password-change-required header re-fetches whoami and shows the form', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') {
        return { status: 403, body: { detail: 'password change required' },
                headers: { 'x-password-change-required': 'true' } };
      }
      if (url === '/whoami') return { body: whoami('alice', 'analyst', true) };
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  assert.equal(ui.$('#pwChangeCard').hidden, false);
  assert.equal(ui.alerts.length, 0);               // handled quietly, not a raw alert
});

test('a failed request shows a dismissible toast instead of a blocking alert()', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (url === '/assessments' && opts.method === 'POST') return { body: assessment() };
      if (url === '/assessments/asm-1/analyse') return { status: 400, body: { detail: 'not ready yet' } };
      return { body: assessment() };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#analyseBtn').click();
  await settle();

  assert.equal(ui.alerts.length, 0, 'no blocking alert() was called');
  const toast = ui.$('#toastStack .toast');
  assert.ok(toast, 'an error toast was rendered');
  assert.ok(toast.textContent.includes('not ready yet'));

  toast.querySelector('.toast-close').click();
  assert.equal(ui.$('#toastStack').children.length, 0, 'dismiss button removes the toast');
});

test('starting an assessment opens an SSE stream that live-appends new events', async () => {
  const ui = boot({
    respond: (url) => (url === '/login') ? { body: whoami('alice', 'analyst') } : { body: assessment() },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();

  assert.equal(ui.eventSources.length, 1);
  assert.equal(ui.eventSources[0].url, '/assessments/asm-1/stream');
  assert.ok(typeof ui.eventSources[0].onmessage === 'function');

  ui.eventSources[0].onmessage({
    data: JSON.stringify({ level: 'decision', message: 'Live-streamed update', ts: '2024-01-01T00:00:01' }),
    lastEventId: '5',
  });
  assert.match(ui.$('#events').innerHTML, /Live-streamed update/);
});

test('the SSE stream skips replaying an event already known when it connected', async () => {
  const ui = boot({
    respond: (url) => (url === '/login') ? { body: whoami('alice', 'analyst') }
                     : { body: assessment({ events: [{ level: 'info', message: 'Already rendered', ts: '2024-01-01T00:00:00' }] }) },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();                 // skipBelow is captured here as current.events.length === 1

  ui.eventSources[0].onmessage({                           // index 0 -- the event already known
    data: JSON.stringify({ level: 'info', message: 'Already rendered', ts: '2024-01-01T00:00:00' }), lastEventId: '0',
  });
  assert.equal(ui.$('#events').innerHTML.match(/Already rendered/g).length, 1, 'not rendered twice');

  ui.eventSources[0].onmessage({                           // index 1 -- genuinely new
    data: JSON.stringify({ level: 'decision', message: 'Genuinely new', ts: '2024-01-01T00:00:01' }), lastEventId: '1',
  });
  assert.match(ui.$('#events').innerHTML, /Genuinely new/);
});

test('signing out closes the SSE stream', async () => {
  const ui = boot({
    respond: (url) => (url === '/login') ? { body: whoami('alice', 'analyst') } : { body: assessment() },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#signOutBtn').click();
  await settle();

  assert.equal(ui.eventSources[0].closed, true);
});

test('signing out clears state and shows the login form again', async () => {
  const ui = boot({
    respond: (url) => url === '/login' ? { body: whoami('alice', 'analyst') } : { body: {} },
  });
  await settle();
  await signIn(ui);
  ui.$('#signOutBtn').click();
  await settle();
  const out = ui.calls.find((c) => c.url === '/logout');
  assert.ok(out);
  assert.equal(ui.csrfOf(out), CSRF);
  assert.equal(ui.$('#authCard').hidden, false);
  assert.equal(ui.$('#mainApp').hidden, true);
});

test('report generation POSTs with credentials+CSRF and downloads the PDF', async () => {
  const ui = boot({
    respond: (url) => url === '/login' ? { body: whoami('alice', 'analyst') } : { body: assessment() },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#reportBtn').click();
  await settle();
  const call = ui.calls.find((c) => c.url === '/assessments/asm-1/report');
  assert.ok(call);
  assert.equal(call.opts.credentials, 'same-origin');
  assert.equal(ui.csrfOf(call), CSRF);
  assert.deepEqual(ui.downloads.map((d) => d.download), ['VAPT-asm-1.pdf']);
});

test('evidence-pack download POSTs with credentials+CSRF and downloads the zip', async () => {
  const ui = boot({
    respond: (url) => url === '/login' ? { body: whoami('alice', 'analyst') } : { body: assessment() },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  ui.$('#evidencePackBtn').click();
  await settle();
  const call = ui.calls.find((c) => c.url === '/assessments/asm-1/evidence-pack');
  assert.ok(call);
  assert.equal(call.opts.credentials, 'same-origin');
  assert.equal(ui.csrfOf(call), CSRF);
  assert.deepEqual(ui.downloads.map((d) => d.download), ['evidence-pack-asm-1.zip']);
});

// ---- role-gated UI --------------------------------------------------------------------------------

test('a lead sees Approve/Deny on a pending approval; an analyst does not', async () => {
  const withApproval = assessment({
    findings: [{ id: 'f1', title: 't', asset: 'a', severity: 'high', status: 'suspected', validation_status: 'not_validated',
                 source_tools: ['nmap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [] }],
    approvals: [{ id: 'appr-1', action: 'validate', state: 'pending', outcome: '',
                  requested_by: 'alice', decided_by: '', executed_by: '' }],
  });
  for (const [role, expectButtons] of [['lead', true], ['analyst', false], ['admin', true]]) {
    const ui = boot({
      respond: (url) => {
        if (url === '/login') return { body: whoami('u', role) };
        if (url === '/admin/users') return { body: [] };
        return { body: withApproval };
      },
    });
    await settle();
    await signIn(ui);
    ui.$('#createBtn').click();
    await settle();
    const buttons = ui.$('#approvals').querySelectorAll('button');
    assert.equal(buttons.length > 0, expectButtons, `role=${role}`);
    if (!expectButtons) assert.match(ui.$('#approvals').textContent, /Awaiting a 'lead' or 'admin'/);
  }
});

test('a viewer does not see the request-active-validation button on a critical finding', async () => {
  const f = { id: 'f1', title: 't', asset: 'a', severity: 'critical', status: 'suspected', validation_status: 'not_validated',
              priority: 'P1', confidence: 0.9, risk_score: 90, source_tools: ['nmap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [] };
  const ui = boot({
    respond: (url) => url === '/login' ? { body: whoami('v', 'viewer') } : { body: assessment({ findings: [f] }) },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();
  assert.equal(ui.$('#findings').querySelector('button'), null);
});

test('the admin panel only appears for role=admin, and loads the user list', async () => {
  const ui = boot({
    respond: (url) => {
      if (url === '/login') return { body: whoami('carol', 'admin') };
      if (url === '/admin/users') return { body: [{ username: 'bob', role: 'lead', disabled: false, must_change_password: false }] };
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui, 'carol');
  await settle();
  assert.equal(ui.$('#adminCard').hidden, false);
  assert.match(ui.$('#userList').textContent, /bob/);
  assert.match(ui.$('#userList').textContent, /lead/);
});

test('admin panel hidden for a non-admin role', async () => {
  const ui = boot({ respond: (url) => url === '/login' ? { body: whoami('alice', 'analyst') } : { body: {} } });
  await settle();
  await signIn(ui);
  assert.equal(ui.$('#adminCard').hidden, true);
});

test('creating a user posts with CSRF and clears the form on success', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('carol', 'admin') };
      if (url === '/admin/users' && opts.method === 'POST') return { body: { username: 'newbie', role: 'analyst', must_change_password: true } };
      if (url === '/admin/users') return { body: [] };
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui, 'carol');
  await settle();
  ui.$('#newUserName').value = 'newbie';
  ui.$('#newUserPassword').value = 'a-strong-temp-pw-1';
  ui.$('#createUserBtn').click();
  await settle();
  const call = ui.calls.find((c) => c.url === '/admin/users' && c.opts.method === 'POST');
  assert.equal(ui.csrfOf(call), CSRF);
  assert.equal(ui.$('#newUserName').value, '');
  assert.match(ui.$('#adminStatus').textContent, /newbie/);
});

test('admin reset-password shows the one-time temporary password from the server response', async () => {
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('carol', 'admin') };
      if (url === '/admin/users') return { body: [{ username: 'bob', role: 'lead', disabled: false, must_change_password: false }] };
      if (url.includes('/reset-password')) return { body: { temporary_password: 'TEMP-xyz-123' } };
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui, 'carol');
  await settle();
  const resetBtn = [...ui.$('#userList').querySelectorAll('button')].find((b) => b.textContent === 'Reset pw');
  resetBtn.click();
  await settle();
  assert.match(ui.$('#adminStatus').textContent, /TEMP-xyz-123/);
});

// ---- rendering safety (regression coverage for the stored-XSS fix) ------------------------------

test('scanner-derived text and every server-supplied identity render as inert text, never markup', async () => {
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
  const ui = boot({
    respond: (url) => url === '/login' ? { body: whoami(MALICIOUS, 'lead') } : { body: hostile },
  });
  await settle();
  await signIn(ui, 'x');
  ui.$('#createBtn').click();
  await settle();

  assert.equal(ui.w.__xss, undefined, 'injected handler must never run');
  for (const id of ['#whoami', '#plan', '#events', '#findings', '#approvals']) {
    assert.equal(ui.$(id).querySelector('img'), null, `${id} contains a live <img>`);
    const injected = [...ui.$(id).querySelectorAll('b')].filter((b) => b.textContent === 'bold');
    assert.equal(injected.length, 0, `${id} rendered the payload's <b> as live markup`);
  }
  for (const id of ['#plan', '#events', '#findings', '#approvals', '#whoami']) {
    assert.ok(ui.$(id).textContent.includes('<img src=x'), `${id} should show the payload as visible text`);
  }
  assert.match(ui.$('#findings').innerHTML, /onclick="requestApproval\('raw-1',this\)"/);
});

test('a hostile username in the admin user list renders as inert text', async () => {
  const ui = boot({
    respond: (url) => {
      if (url === '/login') return { body: whoami('carol', 'admin') };
      if (url === '/admin/users') return { body: [{ username: MALICIOUS, role: 'viewer', disabled: false, must_change_password: false }] };
      return { body: {} };
    },
  });
  await settle();
  await signIn(ui, 'carol');
  await settle();
  assert.equal(ui.$('#userList').querySelector('img'), null);
  assert.ok(ui.$('#userList').textContent.includes('<img src=x'));
});

test('the approval request button passes only the finding id, never scanner text', async () => {
  const f = { id: 'raw-1', title: `it's "bad"`, asset: '10.10.10.5', severity: 'high', priority: 'P2',
              status: 'suspected', validation_status: 'not_validated', confidence: 0.5, risk_score: 50,
              source_tools: ['zap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [] };
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (opts.method === 'POST' && /\/approvals$/.test(url)) return { body: {} };
      return { body: assessment({ findings: [f] }) };
    },
  });
  await settle();
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

test('changing a finding\'s remediation select posts the new status', async () => {
  const f = { id: 'raw-1', title: 'SQLi', asset: '10.10.10.5', severity: 'high', priority: 'P2',
             status: 'suspected', validation_status: 'validated', confidence: 0.5, risk_score: 50,
             source_tools: ['zap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [],
             remediation_status: 'open', remediation_updated_by: '' };
  const ui = boot({
    respond: (url, opts) => {
      if (url === '/login') return { body: whoami('alice', 'analyst') };
      if (opts.method === 'POST' && /\/remediation\?status=fixed$/.test(url)) return { body: {} };
      return { body: assessment({ findings: [f] }) };
    },
  });
  await settle();
  await signIn(ui);
  ui.$('#createBtn').click();
  await settle();

  const select = ui.$('#findings select');
  assert.ok(select, 'a remediation select is rendered for a non-viewer role');
  select.value = 'fixed';
  select.dispatchEvent(new ui.w.Event('change'));
  await settle();

  assert.ok(ui.calls.some((c) => /\/assessments\/asm-1\/findings\/raw-1\/remediation\?status=fixed$/.test(c.url)
                               && c.opts.method === 'POST'));
});

test('a viewer sees the remediation status as read-only text, not a select', async () => {
  const f = { id: 'raw-1', title: 'SQLi', asset: '10.10.10.5', severity: 'high', priority: 'P2',
             status: 'suspected', validation_status: 'validated', confidence: 0.5, risk_score: 50,
             source_tools: ['zap'], cve: [], cwe: [], owasp: [], mitre_attack: [], merged_from: [],
             remediation_status: 'in_progress', remediation_updated_by: 'bob' };
  const ui = boot({
    respond: (url) => (url === '/login') ? { body: whoami('victor', 'viewer') } : { body: assessment({ findings: [f] }) },
  });
  await settle();
  await signIn(ui, 'victor');
  ui.$('#createBtn').click();
  await settle();

  assert.equal(ui.$('#findings select'), null);
  assert.match(ui.$('#findings').innerHTML, /in_progress/);
});

// ---- motion system ------------------------------------------------------------------------------

test('static app buttons are bound for motion at load', async () => {
  const ui = boot();
  await settle();
  for (const sel of ['#signInBtn', '#createBtn', '#importBtn', '#analyseBtn', '#reportBtn']) {
    assert.equal(ui.$(sel).dataset.fxBound, '1', `${sel} not bound`);
  }
});
