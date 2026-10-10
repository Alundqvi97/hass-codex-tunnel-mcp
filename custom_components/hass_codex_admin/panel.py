"""Local HA frontend panel; standard platform registration and lifecycle."""
from pathlib import Path


async def register_panel(hass):
    from homeassistant.components.http import StaticPathConfig
    from homeassistant.components.panel_custom import async_register_panel
    path = Path(__file__).parent / "panel.js"
    await hass.http.async_register_static_paths([StaticPathConfig("/hass_codex_admin/panel.js", str(path), False)])
    await async_register_panel(hass, frontend_url_path="hass-codex-admin",
        webcomponent_name="hass-codex-admin", sidebar_title="Administrator approvals",
        sidebar_icon="mdi:shield-check", module_url="/hass_codex_admin/panel.js", require_admin=True)
