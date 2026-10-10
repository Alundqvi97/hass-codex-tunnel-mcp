// Actual panel DOM + real native login/WS + scoped MCP in disposable Core.
const {chromium} = require('playwright');
let stage = 'sandboxed-browser-launch';
const scrub = value => {
  let message = String(value);
  for (const secret of [process.env.ADMIN_BROWSER_PASSWORD, process.env.ADMIN_BROWSER_CONNECTOR]) {
    if (secret) message = message.split(secret).join('[redacted]');
  }
  return message.replace(/hca_[A-Za-z0-9_-]{43}/g, '[redacted]').replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[redacted]');
};
const checkpoint = value => { stage = value; console.log('BROWSER_STAGE='+value); };
let ownedBrowser;
let stopping = false;
const closeOwnedBrowser = async () => {
  if (ownedBrowser) await ownedBrowser.close();
  console.log('BROWSER_CLEANUP=COMPLETE');
};
process.once('SIGTERM', () => {
  stopping = true;
  if (ownedBrowser) closeOwnedBrowser().then(() => process.exit(1)).catch(() => { process.exitCode = 1; });
});
(async () => {
  const base = process.env.ADMIN_BROWSER_BASE;
  const browser = await chromium.launch({executablePath: process.env.ADMIN_BROWSER_EXECUTABLE, chromiumSandbox: true, headless: true, timeout: 25000});
  ownedBrowser = browser;
  try {
    if (stopping) throw new Error('fixture startup interrupted');
    const context = await browser.newContext({serviceWorkers: 'block'});
    const ownedOrigin = url => {
      const target = new URL(url);
      if (target.protocol === 'ws:') target.protocol = 'http:';
      else if (target.protocol === 'wss:') target.protocol = 'https:';
      return target.origin === base;
    };
    await context.route('**/*', route => ownedOrigin(route.request().url()) ? route.continue() : route.abort());
    const page = await context.newPage();
    page.on('pageerror', error => console.error('BROWSER_PAGE_ERROR='+scrub(error.message)));
    page.on('websocket', socket => socket.on('socketerror', error => console.error('BROWSER_WS_ERROR='+scrub(error))));
    page.on('console', message => { if (/^FIXTURE_(?:LOGIN_STAGE|OWNER_CODE)=[a-z_-]+$/.test(message.text())) console.log(message.text()); });
    checkpoint('panel-load');
    // Core serves this task-owned document over an actual loopback connection.
    // A Playwright-fulfilled navigation has no real peer address and Chrome's
    // local-network check then rejects native WS. Do not disable that check.
    await page.goto(base+'/__admin_browser_fixture');
    if (!(await page.evaluate(base => location.origin === base && document.characterSet === 'UTF-8' && isSecureContext && !!crypto.subtle, base))) throw new Error('owned UTF-8 loopback secure origin required for PKCE');
    await page.setContent('<form><label>Username<input name="username" autocomplete="off"></label><label>Password<input name="password" type="password" autocomplete="off"></label><button>Local fixture login</button></form><hass-codex-admin hidden></hass-codex-admin>');
    await page.addScriptTag({url: base+'/hass_codex_admin/panel.js'});
    await page.evaluate(({base}) => {
      const form = document.querySelector('form');
      form.onsubmit = async event => {
        event.preventDefault();
        const bytes = crypto.getRandomValues(new Uint8Array(48));
        const verifier = btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        console.log('FIXTURE_LOGIN_STAGE=pkce-created');
        const post = async (path, value) => {
          const response = await fetch(base+path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(value)});
          if (response.status !== 200) throw new Error('native login request rejected: '+response.status);
          return response.json();
        };
        const flow = await post('/auth/login_flow', {client_id:base, handler:['homeassistant', null], redirect_uri:base+'/auth/callback', code_challenge:challenge, code_challenge_method:'S256'});
        console.log('FIXTURE_LOGIN_STAGE=flow-created');
        const username = form.elements.namedItem('username').value;
        const password = form.elements.namedItem('password').value;
        form.elements.namedItem('password').value = '';
        const result = await post('/auth/login_flow/'+flow.flow_id, {client_id:base, username, password});
        console.log('FIXTURE_LOGIN_STAGE=credentials-submitted');
        if (result.type !== 'create_entry') throw new Error('native login failed');
        const response = await fetch(base+'/auth/token', {method:'POST', body:new URLSearchParams({grant_type:'authorization_code', client_id:base, code:result.result, code_verifier:verifier})});
        const tokens = await response.json();
        if (!tokens.access_token) throw new Error('native token exchange failed');
        console.log('FIXTURE_LOGIN_STAGE=token-created');
        const token = tokens.access_token; // closure only; never a remote connector credential
        form.remove();
        const panel = document.querySelector('hass-codex-admin'); panel.hidden = false;
        console.log('FIXTURE_LOGIN_STAGE=panel-binding');
        panel.hass = {callWS: command => new Promise((resolve, reject) => {
          const ws = new WebSocket(base.replace('http:', 'ws:')+'/api/websocket');
          const deadline = setTimeout(() => {ws.close(); reject(new Error('bounded WS timeout'));}, 8000);
          ws.onopen = () => console.log('FIXTURE_LOGIN_STAGE=ws-open');
          ws.onmessage = event => {
            const value = JSON.parse(event.data);
            if (value.type === 'auth_required') ws.send(JSON.stringify({type:'auth', access_token:token}));
            else if (value.type === 'auth_ok') {console.log('FIXTURE_LOGIN_STAGE=ws-authenticated'); ws.send(JSON.stringify({id:1, ...command}));}
            else if (value.type === 'result') {console.log(value.success ? 'FIXTURE_LOGIN_STAGE=owner-command-approved' : 'FIXTURE_OWNER_CODE='+value.error.code); clearTimeout(deadline); ws.close(); value.success ? resolve(value.result) : reject(value.error);}
            else if (value.type === 'auth_invalid') {clearTimeout(deadline); ws.close(); reject(value);}
          };
          ws.onclose = event => {clearTimeout(deadline); reject(new Error('fixture WS closed: '+event.code));};
          ws.onerror = () => {console.log('FIXTURE_LOGIN_STAGE=ws-failed'); clearTimeout(deadline); reject(new Error('fixture WS failed'));};
        })};
      };
    }, {base});
    checkpoint('native-login');
    await page.getByLabel('Username', {exact:true}).fill(process.env.ADMIN_BROWSER_USERNAME);
    await page.getByLabel('Password', {exact:true}).fill(process.env.ADMIN_BROWSER_PASSWORD);
    await page.getByRole('button', {name:'Local fixture login', exact:true}).click();
    checkpoint('native-owner-panel-ready');
    await page.getByRole('button', {name:'Issue a connection credential', exact:true}).waitFor();
    checkpoint('issue-connection');
    await page.getByRole('button', {name:'Issue a connection credential', exact:true}).click();
    await page.waitForFunction(() => !!document.querySelector('hass-codex-admin > p:last-of-type')?.textContent, null, {timeout:10000});
    const issueMessage = await page.locator('hass-codex-admin > p').last().textContent();
    if (!issueMessage.includes('Save this credential privately now')) throw new Error('owner connection issuance failed: '+issueMessage);
    const credentials = (await page.locator('hass-codex-admin').textContent()).match(/hca_[A-Za-z0-9_-]{43}/g);
    if (!credentials || credentials.length !== 1) throw new Error('one-time scoped credential missing');
    const connection = issueMessage.match(/^Connection ([a-f0-9]{32})\./);
    if (!connection) throw new Error('issued connection identity missing');
    checkpoint('revoke-connection');
    await page.getByRole('button', {name:'Manage connections', exact:true}).click();
    const issuedCard = page.locator('section').filter({hasText:connection[1]});
    await issuedCard.getByRole('button', {name:'Revoke this connection', exact:true}).click();
    // Click dispatch is not the asynchronous native revocation acknowledgment.
    // Wait for the actual owner's response to remove this exact connection card.
    await issuedCard.waitFor({state:'detached'});
    if ((await page.locator('hass-codex-admin').textContent()).includes(credentials[0])) throw new Error('credential remained in panel');
    const revokedStatus = await page.evaluate(async ({base, credential}) => (await fetch(base+'/api/hass_codex_admin/mcp', {method:'POST', headers:{Authorization:'Bearer '+credential}, body:'{}'})).status, {base, credential:credentials[0]});
    if (revokedStatus !== 401) throw new Error('revoked credential accepted');
    checkpoint('review-and-approve');
    await page.getByRole('button', {name:'Refresh tasks', exact:true}).click();
    await page.getByRole('button', {name:'Approve this exact task once', exact:true}).click();
    await page.getByText('Review the task and confirm its effects first.', {exact:true}).waitFor();
    for (const checkbox of await page.getByRole('checkbox').all()) await checkbox.check();
    await page.getByRole('button', {name:'Approve this exact task once', exact:true}).click();
    try {
      await page.getByRole('heading', {name:/— approved/}).waitFor({timeout:10000});
    } catch (error) {
      const state = await page.locator('hass-codex-admin h3').allTextContents();
      console.error('BROWSER_TASK_HEADINGS='+scrub(JSON.stringify(state)));
      throw error;
    }
    if (await page.locator('section script').count()) throw new Error('untrusted definition created a script element');
    const call = async (name, args, expectedError) => page.evaluate(async ({base, credential, name, args, expectedError}) => {
      const response = await fetch(base+'/api/hass_codex_admin/mcp', {method:'POST', headers:{Authorization:'Bearer '+credential, 'Content-Type':'application/json', Accept:'application/json'}, body:JSON.stringify({jsonrpc:'2.0', id:1, method:'tools/call', params:{name, arguments:args}})});
      const body = await response.json(); const content = JSON.parse(body.result.content[0].text);
      if (body.result.isError) {if (content.error === expectedError) return {error:content.error}; throw new Error('scoped tool failed');} return content.result;
    }, {base, credential:process.env.ADMIN_BROWSER_CONNECTOR, name, args, expectedError});
    const args = {task:process.env.ADMIN_BROWSER_TASK, plan_hash:process.env.ADMIN_BROWSER_HASH};
    checkpoint('approved-mcp-execute');
    const applied = await call('admin_execute', args);
    if (applied.operations[0].status !== 'applied') throw new Error('approved mutation did not apply');
    await page.getByRole('button', {name:'Refresh tasks', exact:true}).click();
    await page.getByText(/stored_definition_or_ha_state_verified/).waitFor();
    checkpoint('mcp-rollback');
    const rolled = await call('admin_rollback', args);
    if (rolled.operations[0].status !== 'rolled_back') throw new Error('rollback not verified');
    await page.getByRole('button', {name:'Refresh tasks', exact:true}).click();
    await page.getByRole('button', {name:'Revoke remaining operations', exact:true}).click();
    await page.getByRole('heading', {name:/— revoked/}).waitFor();
    checkpoint('native-selector-handoff');
    const flowTask = await call('admin_propose', {operations:[{family:'integration', action:'reconfigure', target:process.env.ADMIN_BROWSER_FLOW_ENTRY, value:{}}]});
    await page.getByRole('button', {name:'Refresh tasks', exact:true}).click();
    const flowCard = page.locator('hass-codex-admin section').filter({hasText:flowTask.id});
    await flowCard.getByRole('checkbox').check();
    await flowCard.getByRole('button', {name:'Approve this exact task once', exact:true}).click();
    await flowCard.getByRole('heading', {name:/— approved/}).waitFor({timeout:5000});
    const flowArgs = {task:flowTask.id, plan_hash:flowTask.hash};
    const pending = await call('admin_execute', flowArgs, 'outcome_requires_reconciliation');
    if (pending.error !== 'outcome_requires_reconciliation') throw new Error('native handoff prematurely completed');
    await page.getByRole('button', {name:'Refresh tasks', exact:true}).click();
    await flowCard.getByRole('button', {name:'Open secure native input', exact:true}).click();
    await flowCard.getByLabel('next_step_id', {exact:true}).selectOption('0');
    await flowCard.getByRole('button', {name:'Continue in native HA', exact:true}).click();
    const pin = flowCard.getByLabel('pin', {exact:true});
    if (await pin.getAttribute('type') !== 'password') throw new Error('native secret selector was visible input');
    await pin.fill(process.env.ADMIN_BROWSER_PASSWORD);
    const continueNative = flowCard.getByRole('button', {name:'Continue in native HA', exact:true});
    await continueNative.click(); // Required numeric input is still empty.
    if (await pin.inputValue() !== process.env.ADMIN_BROWSER_PASSWORD) throw new Error('local validation discarded native password');
    await flowCard.getByLabel('choices', {exact:true}).selectOption(['1']);
    await flowCard.getByLabel('limit', {exact:true}).fill('3.5');
    await flowCard.getByLabel('notes', {exact:true}).fill('first\nsecond');
    for (const optional of ['extra_limit', 'extra_choice']) {
      const include = flowCard.getByLabel('Set optional '+optional, {exact:true});
      await include.check();
      await continueNative.click();
      if (await pin.inputValue() !== process.env.ADMIN_BROWSER_PASSWORD) throw new Error('blank optional value dispatched or discarded native password');
      await include.uncheck();
    }
    await flowCard.getByLabel('Set optional clear_choices', {exact:true}).check();
    await continueNative.click();
    await flowCard.getByText(/native_terminal_result_verified/).waitFor({timeout:5000});
    const flowOutcome = await call('admin_status', {task:flowTask.id});
    if (flowOutcome.operations[0].status !== 'applied' || JSON.stringify(flowOutcome).includes(process.env.ADMIN_BROWSER_PASSWORD)) throw new Error('native selector result or secret suppression failed');
    console.log('ACTUAL_OWNER_PANEL_BROWSER=PASS login issue revoke plan consent execute outcome rollback reject native-menu-selectors-password');
  } finally {await closeOwnedBrowser();}
})().catch(error => { console.error('BROWSER_FAILURE_STAGE='+stage+'\n'+scrub(error.message || error.code || 'browser fixture failed')); process.exitCode=1; });
