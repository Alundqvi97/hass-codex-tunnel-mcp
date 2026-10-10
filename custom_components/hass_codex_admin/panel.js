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
      const windowLabel = this.element('label', ' I will keep other editors away from the named objects until this task expires or is revoked; this is cooperation, not an HA lock.');
      const windowCheck = document.createElement('input'); windowCheck.type = 'checkbox'; windowLabel.prepend(windowCheck);
      if (task.plan.edit_window?.required) card.append(windowLabel);
      card.append(this.button('Approve this exact task once', async () => {
        if (!check.checked) { this.message.textContent = 'Review the task and confirm its effects first.'; return; }
        await this.call('approve', {task: task.id, plan_hash: task.hash, confirm_effects: true, confirm_edit_window: windowCheck.checked}); await this.refresh();
      }));
      card.append(this.button('Revoke remaining operations', async () => { await this.call('revoke', {task: task.id, plan_hash: task.hash}); await this.refresh(); }));
      for (const item of task.operations) {
        if (item.status !== 'uncertain' || !item.result?.result?.owner_input_required) continue;
        const flow = this.element('div'); card.append(flow);
        const command = (action, fields = {}) => this._hass.callWS({type: 'hass_codex_admin/flow', action, task: task.id, plan_hash: task.hash, operation: item.n, ...fields});
        const show = state => {
          flow.replaceChildren(this.element('p', 'Native integration input stays here in HA. Starting a flow is not completion; an interrupted flow remains uncertain.'));
          const inputs = [];
          for (const field of state.fields) {
            const label = this.element('label', field.name);
            const input = document.createElement(field.kind === 'select' ? 'select' : field.multiline ? 'textarea' : 'input');
            if (field.kind === 'select') {
              input.multiple = field.multiple;
              if (!field.multiple) { const empty = this.element('option', 'Choose a value'); empty.value = ''; input.append(empty); }
              for (const [index, choice] of field.choices.entries()) { const option = this.element('option', String(choice)); option.value = String(index); input.append(option); }
            } else {
              if (input.tagName === 'INPUT') input.type = field.kind === 'boolean' ? 'checkbox' : ['integer', 'number'].includes(field.kind) ? 'number' : field.password || /password|token|secret|key|credential|pin/i.test(field.name) ? 'password' : 'text';
              for (const key of ['min', 'max', 'step']) if (field[key] !== undefined) input[key] = field[key];
            }
            input.autocomplete = 'off'; input.required = ['integer', 'number'].includes(field.kind) || field.kind === 'select' && !field.multiple; label.append(input); flow.append(label);
            let include;
            if (!field.required) { const optional = this.element('label', ` Set optional ${field.name}`); include = document.createElement('input'); include.type = 'checkbox'; optional.prepend(include); flow.append(optional); }
            inputs.push([field, input, include]);
          }
          flow.append(this.button('Continue in native HA', async () => {
            const value = {};
            // Validate all included controls before clearing any secret or
            // dispatching. Included optional numbers/selections need a value.
            for (const [field, input, include] of inputs) {
              if (include && !include.checked) continue;
              if (!input.checkValidity() || ['integer', 'number'].includes(field.kind) && !input.value || field.kind === 'select' && !field.multiple && !input.value) {
                this.message.textContent = 'Complete the required native inputs using valid values.'; return;
              }
            }
            for (const [field, input, include] of inputs) {
              if (include && !include.checked) { input.value = ''; continue; }
              value[field.name] = field.kind === 'select' ? field.multiple ? [...input.selectedOptions].map(option => field.choices[Number(option.value)]) : field.choices[Number(input.value)] : field.kind === 'boolean' ? input.checked : ['integer', 'number'].includes(field.kind) ? Number(input.value) : input.value;
              input.value = '';
            }
            const next = await command('submit', inputs.length ? {input: value} : {});
            if (next.completed) await this.refresh(); else show(next);
          }));
          flow.append(this.button('Cancel native handoff', async () => { for (const [, input] of inputs) input.value = ''; await command('cancel'); await this.refresh(); }));
        };
        flow.append(this.button('Open secure native input', async () => show(await command('status'))));
      }
      this.tasks.append(card);
    }
  }
}
customElements.define('hass-codex-admin', AdministratorPanel);
