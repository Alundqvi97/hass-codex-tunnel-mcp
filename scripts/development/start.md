# Native administrator development

This is checked-in, secret-free development setup, relocated from the existing cloud draft. It does not publish an environment, change workspace authentication/network settings, install a system service, connect a tunnel or deploy Home Assistant.

## Preserve and select PR #2

Repository: `Alundqvi97/hass-codex-tunnel-mcp`; branch `security/ha-mcp-phase2d-candidates`; existing draft PR #2. Reviewed source gate: `a7ad7a6a3362262e0a5f3b8d8a04998106d42acc`. This is an ancestry gate, not equality with a changing GitHub HEAD. Production operation does not contact GitHub to validate its revision.

Before engineering, inspect `git status --short`, `git branch --show-current`, `git rev-parse HEAD`, `git log --oneline -8` and the applicable AGENTS.md. Fetch the named branch without changing the checkout. Read current PR metadata using `gh api repos/Alundqvi97/hass-codex-tunnel-mcp/pulls/2`, checking open/draft/unmerged, branch identity and exact head SHA. Compare the fetched head/PR head, verify `git merge-base --is-ancestor a7ad7a6a3362262e0a5f3b8d8a04998106d42acc HEAD`, and inspect any intervening changes. Never assume an old remote-tracking ref advanced when only FETCH_HEAD was updated.

If main/wrong ancestry/missing native modules are selected, stop engineering there. Preserve all dirty work and prepare a separate owned checkout/worktree at the verified PR head; do not reset, stash, clean or overwrite. Inspect legitimate descendants before continuing. Detached descendants are permitted after this review. The installer reports the selected HEAD/branch and blocks main, a wrong origin, missing gate ancestry or missing modules. It intentionally makes no automatic branch switch or remote-equality requirement.

## Install once; verify offline

Run as the ordinary non-root workspace user, from a verified candidate checkout:

```sh
bash scripts/development/install.sh --check-base
bash scripts/development/install.sh --setup
bash scripts/development/install.sh --verify
```

`--setup` uses supplied uv/node/Git, Python3.12 for retained offline regressions and Python3.14.2/Core2026.10.0 for native tests. It installs the existing 125-package `requirements/admin-test.lock.txt` with hashes and normal TLS, verifies dependencies, and caches pinned historical upstream fixtures at `fc54437a804858732e4bc927add98e202d879a09` outside the checkout. The only new fixture dependency is aiohasupervisor0.6.0 from Core’s official Supervisor manifest; previously verified locked packages are unchanged. No Home Assistant2024 service or real tunnel is installed. Existing verified environments are reusable; incomplete environments are preserved for diagnosis.

State defaults to `/workspace/.development/hass-codex-tunnel-mcp`; `ADMIN_DEV_STATE` can select another task-owned absolute directory outside the repository. `ADMIN_NATIVE_STATE` may select an existing compatible native development environment. For a fresh venv using an already supplied verified Python3.14.2 executable, set `ADMIN_NATIVE_PYTHON` to that executable; no secret or private setup file is needed. Without it, uv obtains the same version. Caches, bytecode, fixture configs/SQLite, synthetic credentials and logs stay outside Git. The installer snapshots status/worktree/index before and after validation and rejects incidental checkout changes.

Primary validation runs actual isolated Core HTTP/WebSocket/MCP, native owner approval, useful automation/script/helper/dashboard/device workflows, actual process crash/recovery and supported Core restore. Owned fixtures bind loopback and install socket/DNS guards against non-loopback devices/Internet. Retained Phase2L runs follow `.github/workflows/phase2l-offline-only.yml`; broader pytest excludes runtime staging and uses a separate loopback-only guard. Compilation, panel/fixture JS parsing, VM-script parsing only and Git whitespace/isolation checks follow. `--verify` downloads no dependencies or remote state and makes no real tunnel connection.

Optional actual owner-panel browser acceptance requires a sandbox-capable Chromium executable:

```sh
ADMIN_BROWSER_EXECUTABLE=/path/to/sandbox-capable-chromium bash scripts/development/install.sh --setup
```

This uses the separately locked Playwright1.62.1 development client outside the checkout, skips browser download/install scripts and exercises actual panel DOM/native WS. A requested browser failure fails verification; it is not silently skipped or replaced by a mocked approval. The supplied cloud Chromium currently aborts because its SUID sandbox helper is misconfigured; no system fix or sandbox disabling was performed. A compatible runner is an explicit remaining acceptance prerequisite.

The fresh-checkout receipt and exact counts/checksums are in `docs/security/NATIVE_ADMIN_EVIDENCE.json`. Do not count repeated tests as independent coverage. Use `docs/security/RECOVERY_DESIGN.md` for the selected connection, restart, update and restore gates. The old unpublished cloud draft is not a production dependency and was not republished.

## Execution restrictions

No live Probe A, root/sudo, capability change, firewall/cgroup mutation, privileged container, Docker socket/host network, QEMU/HAOS/VM, household/production access, real OAuth/key/tunnel configuration, paid resource, workflow dispatch/retry, host reboot, merge or environment publication. Only this task's nonprivileged loopback instances, synthetic identities/state and owned child processes may run or be removed. Do not edit application/lock/workflow/production files as a side effect of setup. Missing proof stays missing; compilation or synthetic evidence does not establish kernel enforcement, hosted ChatGPT/iPhone or HAOS acceptance.
