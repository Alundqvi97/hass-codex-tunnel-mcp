// Local HA-owned approval UI. Backend definitions are untrusted text.
class AdministratorPanel extends HTMLElement {
  set hass(value) { this._hass = value; if (!this.started) { this.started = true; this.render(); } }
  async call(action, fields = {}) {
    return this._hass.callWS({type: 'hass_codex_admin/approval', action, ...fields});
  }
  element(tag, text) { const node = document.createElement(tag); if (text) node.textContent = text; return node; }
  button(text, work) {
    const button = this.element('button', text);
    button.onclick = async () => { button.disabled = true; try { await work(); } catch (error) { this.message.textContent = error.code || 'Approval unavailable; check your HA owner session.'; } finally { button.disabled = false; } };
    return button;
  }
  render() {
    this.replaceChildren(); this.style.cssText = 'display:block;padding:24px;max-width:1000px;overflow:auto';
    this.append(this.element('h2', 'Administrator task approvals'));
    this.append(this.element('p', 'Use your local HA owner login. Review exact definitions, indirect effects, expiry and rollback; assistant text is not authority. Existing native sessions work after restart; saved approvals do not.'));
    this.message = this.element('p'); this.append(this.message);
    this.append(this.button('Issue a connection credential', async () => {
      const value = await this._hass.callWS({type: 'hass_codex_admin/connection', action: 'issue'});
      this.message.textContent = `Connection ${value.id}. Save this credential privately now; it will not be displayed again: ${value.connector_credential}. Endpoint ${value.path}. It does not approve tasks.`;
    }));
    this.append(this.button('Manage connections', async () => {
      const values = await this._hass.callWS({type: 'hass_codex_admin/connection', action: 'list'});
      this.tasks.replaceChildren(); this.message.textContent = 'Revoking a connection prevents new requests and final dispatch. Configure transport only under separate staging authorization.';
      for (const value of values) {
        const card = this.element('section', `${value.label} — ${value.id} — expires ${new Date(value.expires * 1000).toLocaleString()}`);
        card.append(this.button('Revoke this connection', async () => { await this._hass.callWS({type: 'hass_codex_admin/connection', action: 'revoke', connector_id: value.id}); card.remove(); }));
        this.tasks.append(card);
      }
    }));
    this.append(this.button('Refresh tasks', () => this.refresh()));
    this.tasks = this.element('div'); this.append(this.tasks);
  }
  async refresh() {
    const tasks = await this.call('list'); this.tasks.replaceChildren();
    for (const task of tasks) {
      const card = this.element('section'); card.style.cssText = 'border:1px solid gray;padding:16px;margin:16px 0';
      card.append(this.element('h3', `${task.id} — ${task.status}`));
      card.append(this.element('p', `Expires ${new Date(task.expires * 1000).toLocaleString()}. Caller ${task.user}.`));
      const detail = this.element('pre', JSON.stringify({hash: task.hash, plan: task.plan, operations: task.operations}, null, 2));
      detail.style.cssText = 'white-space:pre-wrap;overflow-wrap:anywhere'; card.append(detail);
      const label = this.element('label', ' I reviewed the exact changes, indirect/security/destructive effects and rollback scope.');
      const check = document.createElement('input'); check.type = 'checkbox'; label.prepend(check); card.append(label);
      card.append(this.button('Approve this exact task once', async () => {
        if (!check.checked) { this.message.textContent = 'Review the task and confirm its effects first.'; return; }
        await this.call('approve', {task: task.id, plan_hash: task.hash, confirm_effects: true}); await this.refresh();
      }));
      card.append(this.button('Revoke remaining operations', async () => { await this.call('revoke', {task: task.id, plan_hash: task.hash}); await this.refresh(); }));
      this.tasks.append(card);
    }
  }
}
customElements.define('hass-codex-admin', AdministratorPanel);
