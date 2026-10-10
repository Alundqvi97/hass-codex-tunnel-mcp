// Actual panel DOM and native owner WebSocket against disposable loopback Core.
const {chromium} = require('playwright');
(async () => {
  const base = process.env.ADMIN_BROWSER_BASE;
  const browser = await chromium.launch({executablePath: process.env.ADMIN_BROWSER_EXECUTABLE, chromiumSandbox: true, headless: true});
  try {
    const context = await browser.newContext({serviceWorkers: 'block'});
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      return url.origin === base ? route.continue() : route.abort();
    });
    const page = await context.newPage();
    await page.goto(base+'/hass_codex_admin/panel.js');
    await page.setContent('<hass-codex-admin></hass-codex-admin>');
    await page.addScriptTag({url: base+'/hass_codex_admin/panel.js'});
    await page.evaluate(({base, token}) => {
      document.querySelector('hass-codex-admin').hass = {callWS: command => new Promise((resolve, reject) => {
        const ws = new WebSocket(base.replace('http:', 'ws:')+'/api/websocket');
        ws.onmessage = event => {
          const value = JSON.parse(event.data);
          if (value.type === 'auth_required') ws.send(JSON.stringify({type:'auth', access_token:token}));
          else if (value.type === 'auth_ok') ws.send(JSON.stringify({id:1, ...command}));
          else if (value.type === 'result') {ws.close(); value.success ? resolve(value.result) : reject(value.error);}
          else if (value.type === 'auth_invalid') {ws.close(); reject(value);}
        };
        ws.onerror = () => reject(new Error('fixture websocket failed'));
      })};
    }, {base, token:process.env.ADMIN_BROWSER_OWNER_TOKEN});
    await page.getByRole('button', {name:'Refresh tasks', exact:true}).click();
    await page.getByRole('button', {name:'Approve this exact task once'}).waitFor();
    await page.getByRole('button', {name:'Approve this exact task once'}).click();
    await page.getByText('Review the task and confirm its effects first.', {exact:true}).waitFor();
    await page.getByRole('checkbox').check();
    await page.getByRole('button', {name:'Approve this exact task once'}).click();
    await page.getByRole('heading', {name:/— approved/}).waitFor();
    if (await page.locator('section script').count()) throw new Error('untrusted definition created DOM script');
    await page.getByRole('button', {name:'Revoke remaining operations'}).click();
    await page.getByRole('heading', {name:/— revoked/}).waitFor();
    console.log('ACTUAL_OWNER_PANEL_BROWSER=PASS');
  } finally {await browser.close();}
})().catch(error => {console.error(error.message); process.exitCode=1;});
