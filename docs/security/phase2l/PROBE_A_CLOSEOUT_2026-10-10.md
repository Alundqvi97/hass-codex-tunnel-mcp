# Probe A source/build closeout and unexecuted release package

2026-10-10, Europe/Stockholm. **SOURCE_OR_BUILD_INCOMPLETE — EXACT BLOCKERS.**
This delivery corrects confirmed source defects and connects more of the existing
architecture. It is not a runnable, accepted native package or a production release.
No native actor, privilege/capability change, cgroup/firewall operation, probe
traffic, VM, production/tunnel connection, runtime approval or private key was used.

## Immutable recovery and review

Reviewed source remains `6a5d752412d7452008addcf93d78197322ecd157`; initial clean
PR #2 delivery was `a394c0a8aa5c39fd25a910e5f55bcb17e80a3f1a`. Their difference
was exactly four documents: plan, engineering review, native package and coverage.
Both earlier `182c8b7c95513b83abc71f2d49ea82adde7ef4fa` and approved gate
`ad5e0c2ba52901c8384597d3cafd26ce3ffb124d` remain ancestors.
During work the owner advanced the branch to
`b2dc4eb05f5bda4ec9b32d443a1abba505543a2b`, adding only 16 Blueprint lines about
reliability and bounded maintenance. Its exact diff was inspected, safely
fast-forwarded, and all uncommitted source/test bytes were checked unchanged.
The reviewed source was not silently replaced. The owner's updated Blueprint and
all 13 workflows are preserved byte-for-byte relative to that legitimate parent.

Source/test revision: `ce7fd5025c94974bb4c800351759342fff560abe`. It has one parent, `b2dc4eb...`, and 24 changed
source/test paths listed below. The documentation-only receipt is reported after
commit; no file hashes its own commit. PR #2 must remain open, draft and unmerged.
No history rewrite, unrelated file edit, dependency/environment/authentication
change or automatically triggered privileged workflow was introduced.

## Finite disposition register

| ID | Current source disposition | Exact remaining boundary |
|---|---|---|
| INT-01 | Earlier activated-root bootstrap fail-stop preserved; package entry rejects wrong loader/guard/context; disabled refusal remains harmless. | **SOURCE_DEFECT:** fixed immutable entry must enclose its initial imports, verifier/guard/package constructors and native loading, not just already constructed arguments; linked to S1/S6. |
| INT-02 | Supervisor cleanup-audit authority preserved. Guardian now has its own authenticated UID-only observer channel and original final deadline. | **SOURCE_DEFECT:** synchronous dispatcher/callback capacity under slow work/floods is not fully bounded; linked to S6. |
| INT-03 | Failed/partial/cancelled work remains distinct from independently verified/incomplete/uncertain cleanup; bad authorities stay quarantined. | **NATIVE_IMPLEMENTATION_MISSING:** actual journal producer, all-exit durable ownership and external final observation; linked to S5/S6. |
| S1 | `NativePackageLoader` reconstructs signed inventory/source export/policy/scopes and an already committed grant; never claims it again. `DescriptorOwner` pins exact open-file descriptions, detects reuse, closes failed acquisitions, and owns allocator/executable handles. | **NATIVE_IMPLEMENTATION_MISSING:** fixed source-pinned entry script, sealed package-FD slot/schema/allocator-to-entry connection, controller-safe trust reconstruction, full partial-startup endpoint/journal custody. No successful end-to-end native package reconstruction test exists. |
| S2 | Sealed G/O audit descriptors; guardian gets existing observer identity; observer gets later guardian identity only through authenticated coordinator release. RUNNING follows service/channel construction. Broker purpose is derived server-side and permits only `numeric_uid_process_absent`. | **RUNTIME_ACCEPTANCE_NOT_EXECUTED:** real cross-process handoff/EOF/capacity/kernel identity. Source routing is connected; it is not an independently accepted complete lifecycle. |
| S3(a) | **CORRECTED:** named SYS_PTRACE=19 and SYS_ADMIN=21; bit21 denied in both capability fields, every set, every role. Fixed metadata inspection alone justifies19 in guardian/observer; ptrace/process_vm/kcmp/pidfd_getfd remain denied. | **RUNTIME_ACCEPTANCE_NOT_EXECUTED:** exact installed role capabilities and libcap/ambient/securebits/UID transitions. |
| S3(b) | **CORRECTED SECCOMP INHERITANCE:** parent common filter does not permanently deny legitimate worker/peer IP; leaf control/helper filters deny IP. Legacy namespace clone flags denied; clone3 denied to leaves, fixed atomic parent mechanism retained. | **NATIVE_IMPLEMENTATION_MISSING:** full compiled BASE/ROLE AppArmor assets, actual cached-NNP BASE establishment, reviewed exec transitions including setpriv-to-Python, root peer endpoint confinement and supervisor owned scope/policy. Root denial depends on those missing assets; do not call the whole confinement requirement complete. |
| S3(c) | **CORRECTED:** bounded no-follow `attr/current` text reader, incarnation/path checks; no forbidden `read_at` path or double decode. Cgroup/network readers corrected too. Installed raw policy hashes and actual mountinfo inspected; nested/escaped mounts rejected. | **RUNTIME_ACCEPTANCE_NOT_EXECUTED:** real proc/securityfs policy layout and immutable runner mount. Complete policy build also needs an available reviewed parser/target. |
| S3 remaining | Native child credential installation connects through policy enforcement; exact equal five-set masks, NOROOT locked, automatic UID drop retained, empty groups, bounding reduction, ambient inheritance. Worker vector clears bounding/inheritable/ambient caps. Empty observer groups avoid redundant SETGID. | **NATIVE_IMPLEMENTATION_MISSING:** complete policy assets/base and supervisor integration; **BUILD_OR_DEPENDENCY_BLOCKED:** AppArmor parser and approved target policy ABI/assets unavailable. Inventory dynamic imports/NSS/config consultation still requires a supported target closure and acceptance. |
| S4 | Partial CO-RE syscall program, externally gated libbpf loader with retained verified ELF FD, exact seven-program catalog, owned detach and bounded decoder. Nanosecond start_boottime ABI is explicit; proc ticks are not substituted. Lost/reordered/duplicate/stale data stay incomplete. Linux reject uses NF_DROP=0 plus reject-expression attribution, not invented NF_REJECT. | **NATIVE_IMPLEMENTATION_MISSING:** map activation/readout, pre-exec attachment proof, socket/cookie/FD reuse, payload/transaction and exact reject/rule/counter correlation. Nonempty native scopes still refuse missing independent attachment proof. **BUILD_OR_DEPENDENCY_BLOCKED:** BPF compiler, libbpf headers and approved BTF/hook ABI absent. No BPF object was built. |
| S5 | Existing unsigned bounded journal, independent audit/composer and typed measurement validation preserved; fixed UID scan now observes pidfd/stat/status without requiring executable on kernel threads or PID1. | **NATIVE_IMPLEMENTATION_MISSING:** both-family ownership/restoration/emergency/complete-resource collectors, actual per-authority journal production/authentication and legitimate external owner of supervisor/final residual absence. Checksums, signed booleans and worker/guardian reports are insufficient. |
| S6 | C guard compiled/linked; nested calls restore enclosing deadline. Own-PID check refuses inherited timer; explicit clone child reinitialize/rearm connected before child callbacks. Native clone refuses missing exact guard before inventory authorization. | **SOURCE_DEFECT:** initial/post-exec guarding, supervisor independent lifetime, every blocking callback/local budget and actual service capacity, bounded partial persistence before irreversible actions and every exit. Exec deletes timers; child rearming does not fix post-exec guarding. Host loss/uninterruptible wait/storage loss stay uncertain. |

The source omissions above are not reclassified as missing signatures or live tests.
The package does not offer a trusted runtime PASS path, even with synthetic complete
records. The external runner is the finite final observation owner; no additional
permanent watcher, signer or production daemon was added.

## Permitted validation and actual scope

Baseline reproduced here: **461 Phase 2L passed; 597 broader passed, 1 optional HA
schema skip**. Before edits, the three S3 reproductions yielded **2 failures and
1 error**, plus 2 existing passing tests, exit1. These results are preserved.
Final expanded suite: **489 Phase 2L passed, 0 failed, 0 skipped; 625 broader
passed, 0 failed, 1 optional HA schema skip**. The latter lacks
`homeassistant.helpers.selector`; no HA service or package was installed.

Commands actually executed:

```sh
bash /workspace/.cloud-environment/hass-codex-tunnel-mcp/install.sh --verify
python3 -B -m unittest discover -s tests/offline -p 'test_phase2l_*.py' -v
python3 -B -m unittest discover -s tests/offline -p 'test_phase2l_probe_a_closeout.py' -v
PYTHONPYCACHEPREFIX=/tmp/probe-a-closeout-pycache python3 -B -m py_compile docs/security/phase2l/*.py
git diff --check
cc -shared -fPIC -std=c11 -Wall -Wextra -Werror -Wl,-z,relro,-z,now docs/security/phase2l/probe_a_deadline_guard.c -o /tmp/probe-a-closeout-build/libprobe_a_guard.so
```

The inspected verify wrapper runs the workflow's pinned fixture
`fc54437a804858732e4bc927add98e202d879a09`, candidate builders only in a fresh
external temporary checkout, source compilation, shell parsing and broader
`pytest tests --ignore=tests/staging` with plugin/cache isolation. It verifies
before/after Git bytes/state. Python and Bash compilation/parse and whitespace
checks passed. No Docker build or staged/live test was run locally.

The 28 new tests exercise actual policy filter intersections, capability policy,
no-follow readers and installed-policy/mount parser, readiness/release decoding,
server-purpose UID catalog, file-description disposal and verified executable
opening, narrowed UID observation, nested guard orchestration, credential
installation order and trace decoder. OS identities, policy installation,
capability syscalls, clock/crypto-authority and transport boundaries are injected.
They do **not** execute clone3, load the guard/trace, start full native actors,
prove dispatcher service capacity, collect real case measurements, or demonstrate
an end-to-end post-exec package. Existing regression coverage is retained.

Separate read-only agent review found additional descriptor/guard/mount/UID/group
issues, corrected here. Native child rearming is subsequent source/build work;
its real timer semantics remain unexecuted. This is adversarial source review,
not qualified independent security certification.

## Build/toolchain and transferable evidence

Existing compiler: GCC `cc (Debian 14.2.0-19) 14.2.0`, GNU binutils2.44;
exact observed versions/paths and ELF metadata are in the artifact. Guard built
as a 16032-byte shared library with SHA256
`349e61090f1c017982eca6c1cfb3ef976a400b212be17248501be8317a5037f9`.
It was never loaded, executed or installed; this host artifact is not an approved
runner dependency. Source/byte hashes do not establish kernel behavior.

Unavailable: clang/BPF backend, `/usr/include/bpf/bpf_helpers.h`,
`bpf_core_read.h`, AppArmor parser, approved target BTF/vmlinux.h and hook ABI.
Existing libbpf discovery is not development-header/build acceptance. No target
version is guessed as approved. A future reviewed toolchain must support CO-RE
`task_struct.start_boottime`, ring-buffer helpers, the exact approved syscall/
netfilter/attachment hooks and the approved policy/NNP transition features.
The descriptor custody target also requires Linux UAPI `F_DUPFD_QUERY=1027`;
unsupported targets refuse, with no inode-only fallback. This is acceptance
machinery, not a new Home Assistant dependency.

Future nonprivileged BPF recipe, **NOT EXECUTED**: with independently supplied
read-only approved vmlinux.h and libbpf include directories, use
`clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -I<approved-target> -I<approved-headers> -c docs/security/phase2l/probe_a_trace.bpf.c -o <external-output>/probe_a_trace.bpf.o`.
First finish the missing measurement source; building this partial program alone
cannot close S4. Compile reviewed policy with the supplied parser into external
output without loading it. Both require version/ABI review; no installation here.

Transferable source/log archive (no dependency binaries/private material):
`/workspace/artifacts/probe-a-closeout-ce7fd50.tar.gz` (96914 bytes), SHA256
`5dbbe3c2472b76f812ad41a72f98b146ba30f7392ebfde862d45d0d160dea807`. It contains original red/baseline/final logs, XML, targeted
results, observed build/protection records, sanitized separate-review findings,
unsigned source hashes, source patch and a verified incremental Git bundle
requiring parent `b2dc4eb...`. `checksums.json` authenticates its individual files
against accidental drift; it is not a signature or runtime approval.

The coverage index records commands/results, all critical hooks, exact source
paths and historical CI. Authenticated GitHub API metadata is now accessible;
full log downloads redirect to a storage host returning Forbidden. No authentication
or network setting was changed. Metadata is read with normal TLS. Scanner monthly-quota/
HTTP402 history is missing independent coverage, not a clean scan; no dispatch,
rerun, billing change or quota workaround is authorized.

## Immutable source CI and publication receipt

Normal push placed `ce7fd5025c94974bb4c800351759342fff560abe` on existing draft PR #2. No competing PR,
force push, manual dispatch/rerun, quota workaround or paid/larger runner.
Public repository and unchanged standard ubuntu-24.04 workflows were checked;
both VM-capable workflows filter their own unchanged paths and did not match.
PR merge `35ecd024b29bfb3f26826937e65686872c7cab5e` has parents
`9203fa88c77877a6d7eaba99909489949061f7da` and source `ce7fd5025c94974bb4c800351759342fff560abe`.
Public run titles resolve to the unique source commit; push runs also link the
full SHA. No inaccessible CI test-log counts are claimed.

| Workflow | Outcome at source commit | Immutable run |
|---|---|---|
| D | SUCCESS | [38042928239](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042928239) |
| D | SUCCESS | [38042925652](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042925652) |
| I | SUCCESS | [38042928217](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042928217) |
| J | SUCCESS | [38042928234](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042928234) |
| K | SUCCESS | [38042928227](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042928227) |
| L | SUCCESS | [38042928257](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042928257) |
| L | SUCCESS | [38042925699](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042925699) |
| E | SUCCESS | [38042925650](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042925650) |
| F | SUCCESS | [38042925648](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042925648) |
| AI | FAILURE | [38042931226](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38042931226) |

All principal offline engineering and E/F packaging succeeded at this exact
source. Packaging success is not native/HAOS/product acceptance. Current AI
scan is FAILURE; its authenticated detail is unavailable. Historical402/quota
failure remains missing independent coverage. It was not retried. A subsequent
docs-only delivery cannot certify its own future CI; final delivery HEAD/status
is verified and reported externally, with identical source/test tree.

## Delivery CI discrepancy — preserved, not retried

Documentation-only delivery `d22bb09357066c718ad856840c1c78dea5f0d664` has the
identical source/test tree. Verified PR merge
`81168c1c30eb888150b7a76313d0e914d8f2dad7` has parents
`9203fa88c77877a6d7eaba99909489949061f7da` and that delivery.
Authenticated API metadata binds each following result to its exact full head SHA.

| Workflow/event | Outcome at d22bb09 | Immutable run |
|---|---|---|
| AI/dynamic | FAILURE | [38043161254](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043161254) |
| J/pull_request | SUCCESS | [38043159372](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043159372) |
| I/pull_request | SUCCESS | [38043159362](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043159362) |
| K/pull_request | SUCCESS | [38043159376](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043159376) |
| D/pull_request | SUCCESS | [38043159375](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043159375) |
| L/pull_request | SUCCESS | [38043159318](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043159318) |
| H/push | SUCCESS | [38043156756](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043156756) |
| D/push | SUCCESS | [38043156759](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043156759) |
| L/push | FAILURE | [38043156777](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043156777) |
| E/push | SUCCESS | [38043156665](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043156665) |
| F/push | SUCCESS | [38043156737](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38043156737) |

Phase 2L push run38043156777, job114187275287, failed step4 with exit1. This
step combines staging, unittest, compilation, shell parsing and Git checks.
The annotation gives no failing command or individual test. Full authenticated
job-log download redirects to storage returning Forbidden; the public step-log
endpoint returns404. The same-source PR run succeeded, but that does not cancel
this failure. Its cause is **unresolved validation**: neither a runner feature
mismatch nor a specific source/test defect is proven. No test assertion was
weakened, no workflow changed and no run retried. This adds no fabricated kernel
or packaging evidence. Current scanner also failed at Processing Request; its
reason cannot be equated to the historical quota error without the missing log.

This receipt records already completed checks. Its own subsequent commit and CI
are recorded in the external delivery artifact/final report rather than hashing
itself or repeatedly publishing to chase a green result.

## Product and release matrix

| Track | Available evidence | Release disposition |
|---|---|---|
| 1 Probe A source/build | Corrections/interfaces, offline results and linked guard above | SOURCE_OR_BUILD_INCOMPLETE; S1/S3/S4/S5/S6 remain |
| 2 Probe A native policy/network/cleanup | No native attempt or kernel case proof | RUNTIME_ACCEPTANCE_NOT_EXECUTED; unauthorized |
| 3 Full HA-MCP auth/admin | Pinned candidate strict marker, fail-closed policy and approval revalidation; previously isolated source/packaged CI | SOURCE_DEFECT: normalized final action/target/caller-bound task grants, revocation/replay and universal hard deny/alternate-route enforcement are not implemented. Hosted identity and actual devices are unverified. |
| 4 HAOS/Supervisor/recovery | Historical VM failed; offline models and source installation contract | NATIVE_IMPLEMENTATION_MISSING: complete sixteen real observers and independent recovery/cleanup. Real install/update/restart/rollback unexecuted. |
| 5 Production change approval | None | EXTERNAL_CONFIGURATION_OR_APPROVAL_REQUIRED; no merge/cutover |

Capability differences against available evidence (live current baseline absent):

| UX requirements | Existing source/fixtures | Missing capability or proof |
|---|---|---|
| UX-01 diagnose; UX-06 integrations | Upstream read tools; strict bootstrap auto-allows only overview | Complete supported scoped reads/logs/traces and authorized repairs/restart/reconfigure with real verification |
| UX-02 create; UX-03 repair; UX-04 delete | Upstream operation tools exist; per-call policy/approval candidate | Final task-scoped action/target/caller authorization, dependency checks, actual writes/readback/restore |
| UX-05 dashboards | Upstream dashboard routes, no product acceptance | Supported multi-card write/readback and safe rollback under same final grant |
| UX-07 bounded approval | Current queue claims/revalidation, no multi-step task grant | One bounded approval journey with revocation/expiry/scope change enforcement; no blanket generic-tool allow |
| UX-08 identity/injection; UX-09 alternate routes | Secret route is a credential; policy checks some normalized nested inputs | Hosted unauthorized-account/workspace denial, caller/session binding, final generic/bulk/WS/proxy/script effect authorization; malicious output cannot broaden grants |
| UX-10 recovery; UX-11 capability/latency | Strict startup and simulated recovery; historical inventory only | Staging repeated requests/reconnect/expiry/restart/update/rollback, retained local automations/admin, measured task latency/manual steps and captured live baseline |
| UX-12 closeout | Sanitized offline receipts | Real per-task affected objects, audit/results and recoverability without leaking secrets |

The one-read bootstrap remains a test baseline, not the final administrator.
Neither `rule_effect` nor existing destructive approval rules were inverted.
Approval-required remains distinct from hard deny. No application source was
changed to introduce a replacement authentication platform. Probe A equipment
must never become an ordinary HA-MCP production dependency. All UX01–12 and the
owner's reliability/finite-maintenance requirements remain release gates.

## One unexecuted acceptance and change sequence

Reuse `phase2g/RECOVERY_BACKUPS.md`, `phase2f/RELEASE_GATE.md`,
`phase2j/FINAL_OFFLINE_READINESS.md` and `phase2k/INSTALLATION_AND_POLICY_PROVISIONING.md`.
Every row below is a separate scope; this document grants no authority.

| Step/owner | Preconditions and proposed ceiling | Evidence, abort and cleanup |
|---|---|---|
| Source/build: engineer + independent reviewer | Close S1/S3/S4/S5/S6 and final-product source gaps; frozen source/artifact/contract versions. Existing nonprivileged tools only here; no new services. | Actual connected positive/negative lifecycle, repeated calls/cancellation, exact unsigned hashes and dependency closure; any regression blocks freeze. |
| Toolchain/assets: reviewer + runner owner | Externally supply approved compiler/headers/BTF/hook ABI/parser/policy and immutable runner image; public verification identities and genuine source/inventory/policy/feature signatures, no private keys in actors/Git. | ABI/content/ancestry/NSS/alias/mount drift aborts. Compile outside source; independent reviewed build hashes. |
| Provisioning: external disposable runner owner | Separate permission for runner-owned supervisor + seven child scopes, immutable source/policies, private ledger/journal and trace reader topology. Proposed standard public x86_64 runner, no paid/larger service, no production. Exact CPU/RAM/storage ceiling must be approved before provisioning. | Readback actual identities/nondelegation/base policy; partial ownership means uncertain teardown. Remove only proven-owned empty groups/trace links; never migrate PIDs or delete foreign resources. |
| One Probe A attempt: runner owner + independent observer | Separate exact source/inventory/policy/boot/session-bound signed attempt claimed once. Maximum240s, cutoff180s, cleanup reserve60s; fixed commands≤8s; one attempt/no retry/no VM. | Independently ready policy/identity/baseline before work; positive DNS/loopback and every denied case/counter; interrupt/drift/loss/uncertain write -> deny-first, owned stop/cleanup. Missing barrier or readback -> blocked, not PASS. |
| Final observation: external runner owner | Finite owner outside acceptance actors; reviewed authority and deadline schedule. No expired probe operation; any later read-only observation needs separately scoped authority. | Both-family baseline restoration, empty descendant scopes, reaped G, O/supervisor shutdown and no residual resources. Host/storage loss remains incomplete/uncertain; preserve journal prefix. |
| HAOS/Supervisor: independent staging operator | New separate authorization after source/security prerequisites, never reuse old VM approval/workflow. Proposed one synthetic guest≤43min, ≤2vCPU/3GiB RAM/16GiB disk, $0 only; exact supported image/Supervisor/digests and network/cleanup scope separately approved. | All16 Phase2J cases, UX01–12, restart/reconnect/expiry/update/recovery/rollback and real local admin outage drill. Any missing case/cleanup fails; no automatic rerun. Existing VM workflow unchanged. |
| Production: owner + release engineer | Separate explicit change approval, independently available local recovery; protected add-on-inclusive backup verified/decrypted/restored in staging, previous image/config/policy/marker identities and supported version compatibility. | Captured baseline admin tasks/latency/manual steps. Scoped staging then approved cutover only. Failure of health/auth/isolation, capability loss, repeated OAuth/approval friction, corrupted policy or unsupported version triggers approved rollback. |
| Rollback: same independent operator | Preapproved previous artifact/options/policy/marker restore; rollback cannot silently disable strictness or delete its history. Never rely on the broken ChatGPT/tunnel path for recovery. | Restore supported add-on-inclusive backup/image/config, verify effective options/data/versions and both permitted/denied admin cases; prove unchanged local automations, independent access and logs/secrets isolation. Failed restore blocks further change. |

Consolidated prerequisites are the five distinct authorization/input rows:
toolchain/assets; provisioning; one runtime attempt; HAOS acceptance; production
cutover. Independent review precedes each applicable gate. Approving one never
approves another. No input alone repairs the remaining source defects.

Smallest defensible next milestone: implement and fixture-test the fixed
immutable post-exec entry/package-FD and guard/journal handoff against the existing
allocator, then close the finite policy/measurement/persistence register using
one externally selected supported runner/toolchain. Do not repeat completed
capability/reader/audit fixes or add another permanent service.

## Exact changed source/test paths

```text
docs/security/phase2l/probe_a_attestation.py
docs/security/phase2l/probe_a_coordinator.py
docs/security/phase2l/probe_a_deadline_guard.c
docs/security/phase2l/probe_a_execution_contract.py
docs/security/phase2l/probe_a_integrated_bootstrap.py
docs/security/phase2l/probe_a_linux_identity.py
docs/security/phase2l/probe_a_linux_launcher.py
docs/security/phase2l/probe_a_native_assembly.py
docs/security/phase2l/probe_a_native_credentials.py
docs/security/phase2l/probe_a_native_deadline.py
docs/security/phase2l/probe_a_native_evidence.py
docs/security/phase2l/probe_a_native_inventory.py
docs/security/phase2l/probe_a_native_package.py
docs/security/phase2l/probe_a_native_policy.py
docs/security/phase2l/probe_a_native_resources.py
docs/security/phase2l/probe_a_native_scopes.py
docs/security/phase2l/probe_a_native_trace.py
docs/security/phase2l/probe_a_readonly_broker.py
docs/security/phase2l/probe_a_role_entrypoints.py
docs/security/phase2l/probe_a_session.py
docs/security/phase2l/probe_a_trace.bpf.c
docs/security/phase2l/probe_a_workload.py
tests/offline/test_phase2l_probe_a_closeout.py
tests/offline/test_phase2l_probe_a_native_delivery.py
```

Probe A execution: UNAUTHORIZED / NOT EXECUTED.
Trusted runtime PASS: UNAVAILABLE.
HAOS/Supervisor acceptance: NO-GO pending separately authorized acceptance.
Production deployment: NOT AUTHORIZED / NOT PERFORMED.
