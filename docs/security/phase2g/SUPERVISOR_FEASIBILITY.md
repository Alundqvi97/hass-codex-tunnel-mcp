# Phase 2G — Genuine HAOS/Supervisor feasibility gate (2026-10-08)

**Result: BLOCKED — no genuine HAOS VM or Supervisor was started.** This is an explicit scope distinction: Phase 2E/2F built real add-on Docker images but did not run Home Assistant Supervisor.

## Read-only hosted-runner evidence

[Actions preflight #37847835408](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37847835408) ran on a disposable `ubuntu-24.04` GitHub-hosted VM, without downloading guests, changing privileges or installing packages:

| Property | Observed |
|---|---|
| Repository | Public `Alundqvi97/hass-codex-tunnel-mcp` |
| Runner | Linux, 4 vCPU, ~15.6 GiB RAM |
| Root filesystem free space | ~87 GiB measured on that job (NOT a durable guarantee) |
| CPU virtualization extensions | Present |
| `/dev/kvm` | Exists but not usable by the workflow user |
| QEMU (`qemu-system-x86_64`, `qemu-img`) | Not preinstalled |
| `virt-install` and OVMF/UEFI firmware | Not preinstalled |
| HAOS image download, new VM, added firewall/network, packages | **None** |

GitHub says standard hosted public-repository Actions jobs are free/unlimited; nested virtualization is technically possible but not officially supported. Neither statement guarantees that a nested guest will boot reliably or that the user's existing workflows have no organizational cost restrictions. A public repository becoming private later would change billing. References: [GitHub runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) and [GitHub nested virtualization caveat](https://github.com/github/docs/blob/main/content/actions/concepts/runners/github-hosted-runners.md).

Home Assistant supports HAOS under KVM with a QCOW2 image, OVMF UEFI, 2 vCPU and at least 2 GiB RAM. [Official installation](https://www.home-assistant.io/installation/linux/) and [developer QEMU procedure](https://developers.home-assistant.io/docs/operating-system/getting-started/).

## Conditional acceptance environment (not provisioned)

**Preferred isolated route:** dedicated ephemeral GitHub-hosted `ubuntu-24.04` runner (not home-infra, HAOS, desktop or UniFi).
- Use a version-and-checksum pinned official HAOS `.qcow2.xz` image; exact version and SHA256 **NOT YET RESOLVED** (must be independently verified before download). Guest UEFI firmware and QEMU packages would be installed **on the disposable CI runner only**.
- Grant the CI job access to `/dev/kvm` temporarily on that runner only, after explicit authorization for the sudo/host-permission change. No production host permission changes.
- Guest budget: initially 2 vCPU / 4 GiB RAM; use sparse disk and enforce explicit max disk usage (e.g. 10 GiB of guest cache), measured before fetch. Official minimum is 2 GiB RAM; add-on pull/startup will consume more.
- Guest networking: independent user-mode NAT or isolated virtual subnet. **No bridged Home/IoT/VPN/Tailscale interface, no physical device passthrough**. Restrict guest egress to official HAOS update/registry resources required to bootstrap; exact domains/IPs must be validated. The guest must NEVER discover or join the home LAN.
- Install only a synthetic HA instance with dummy account/devices. The candidate HA-MCP add-on must be injected through a disposable local-only test repository or alternative Supervisor-recognized development add-on route; prove Supervisor accepts its schema before tool calls.
- Capture only result codes, test counts, timings, sanitized logs and source/image digest. Do not export guest disk, secrets, endpoints or raw configuration.
- Accept criteria: actual Supervisor sees `require_strict_tool_policy`, survives service/guest reboot, refuses missing/corrupt settings and rejected downgrade, watchdog behavior observable, local admin UI works while MCP down, restores original image and preserved policy, and leaks no synthetic secret.
- Cleanup with `trap` even on failure: stop/destroy guest, remove disposable images/firmware state, revoke/delete synthetic tokens, delete test artifacts, end runner job. Require independent proof of cleanup in logs. No persistent service or tunnel.

**Authorization gate:** Creating a new nested VM, installing packages, downloading HAOS, and changing runner KVM permissions goes beyond the no-host-change feasibility probe. The user explicitly requires separate authorization for new VM/host modifications. **Not performed.** If approved, execute only on the disposable GitHub runner; never on any household system. GitHub's lack of guarantees also makes this an optional experiment rather than evidence of guaranteed HAOS acceptance.

**Alternative:** a pre-existing approved, disposable KVM or Supervisor test host could avoid VM creation, but no such host has been independently established here. Generic Docker startup tests are the strongest executed package evidence and are labelled **PACKAGED**, not **SUPERVISOR**.

**Decision:** HAOS/Supervisor release gate remains BLOCKED until an explicitly approved VM or known isolated Supervisor host completes the full acceptance.


## Phase 2H authorized extension — do not conflate stages

The user explicitly authorized one disposable GitHub-hosted standard-runner HAOS virtual guest experiment (not production). [Preflight #37851700140](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851700140) installed runner-only apt dependencies then stopped **before downloading or booting a guest** because the code assumed `/usr/share/OVMF/OVMF_CODE.fd`. Noble's actual OVMF uses `OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`; the script was corrected. Preflight cleanup emitted `PHASE2H_GUEST_PROCESS_CLEANUP=PASS` and `PHASE2H_TEMPORARY_VM_FILES_REMOVED=PASS`. The actual single [VM run #37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) was **still running** when this paragraph was created, so no HAOS/real Supervisor acceptance conclusion is drawn.

Isolated job design: standard public-repository `ubuntu-24.04` runner, official HAOS 18.3 x86_64 OVA QCOW2 asset, GitHub official asset SHA256 check after download, 2 guest vCPUs, 4 GiB RAM, private staged disk and logs, temporary KVM ACL; VM QEMU user-mode NAT with host forwarding bound to loopback only, UID-scoped iptables public web/DNS/NTP egress and private subnet blocking. **IP-only egress is broader than official-domain-only egress**; this is a residual risk, mitigated by disposable synthetic-only machine and no household route. Cleanup script removes temporary ACL/UID/firewall/image and guest processes. No artifact or cache is uploaded, no self-hosted or larger runner, and no paid resources created. Runtime efficacy awaits receipt.
