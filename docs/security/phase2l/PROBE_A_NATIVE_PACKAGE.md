# Probe A disabled native package specification

## Current source/build closeout — 2026-10-10, Europe/Stockholm

**SOURCE_OR_BUILD_INCOMPLETE — EXACT BLOCKERS.** Source/test commit `ce7fd5025c94974bb4c800351759342fff560abe`
continues from inspected owner delivery `b2dc4eb05f5bda4ec9b32d443a1abba505543a2b`,
which changed only the Blueprint after initial `a394c0a...`. Reviewed source stays
`6a5d752...`; approved ancestor `ad5e0c2...` remains. No owner changes were lost.

The reproduced SYS_ADMIN19/21 confusion, inherited socket denial and forbidden
policy-reader path/double decoding are corrected in source. Sealed guardian↔
observer UID-only audit and delayed readiness are connected; signed package/
grant reconstruction, exact FD custody, installed-policy/mount checks, native
role credentials, partial trace source and nested/clone guard contracts are added.
All remain disabled; complete AppArmor/entry/measurement/final evidence/lifetime
wiring is **still missing**, not merely awaiting signatures or live tests.

Final local validation: **489 Phase2L passed; 625 broader passed; one optional
HA schema skip; Python compilation/Bash parse/diff check passed**. Existing C
guard compiled and linked, never loaded/executed. Clang/BPF headers/approved BTF
and AppArmor parser unavailable; no installation or dependency pin changed.
Adversarial self-review and a separate read-only agent pass corrected confirmed
additional defects; neither is security certification.

The finite INT01–03/S1–6 register, exact24 source/test paths, durable sanitized
commands/results/artifact hashes, five-track production matrix, all UX01–12,
owner reliability requirements and unexecuted acceptance/rollback sequence are
in [PROBE_A_CLOSEOUT_2026-10-10.md](PROBE_A_CLOSEOUT_2026-10-10.md) and
[PROBE_A_NATIVE_COVERAGE.json](PROBE_A_NATIVE_COVERAGE.json).
Source/log artifact SHA256: `5dbbe3c2472b76f812ad41a72f98b146ba30f7392ebfde862d45d0d160dea807`.

No workflow/Blueprint/environment/application/lockfile/production edit;
no private signing material, native execution, VM, live evidence or trusted PASS.
PR #2 remains draft/unmerged. Source CI D/I/J/K/L and E/F SUCCESS; AI scanner FAILURE, not clean independent
coverage. Exact run IDs/merge parents are in the closeout/index. Documentation
receipt and its HEAD/status are reported externally without a self-hash. Final product task grants/caller binding/
final effect authorization and full HAOS/recovery observers remain SOURCE
blockers; a read-only permanent replacement is not accepted.

## Candidate sealed package and owner contract (not complete entry wiring)

`NativePackageLoader` accepts canonical v1 public package data with exactly:
`v, context, source, inventory, inventory_signature, source_export,
source_signature, policy, policy_signature, policy_identity, profiles, mount,
backend, groups, parents, grant, grant_signature, activation_signature, ledger,
installed_policy`. Package signature domain: `ProbeA native package v1\0`.
The initial verifier/reader/kernel-fact collector/native guard and full source
anchor are externally supplied by the immutable runner before this package
can select data. No package-selected callable/import/verifier or signing key.
Source, context, signed inventory/export/policy and existing committed grant are
rechecked. `read_package` requires sealed root-owned readonly regular descriptor,
canonical bounded data and descriptor stability; its descriptor is not yet
included in the allocator/config/entry schema, an S1 blocker.

Actor config remains v1: guardian additionally seals `observer-audit` plus actual
observer incarnation; observer additionally seals `guardian-audit`. Authenticated
RUN supplies the later actual guardian identity after independent readiness.
The server chooses guardian-uid-audit purpose; only the fixed numeric UID query
is admitted until the original end. Dispatcher construction precedes RUNNING.
Controller cannot gain this purpose or inspect privileged metadata.

Allocator owns opened/detached endpoints and executable/config handles through
`DescriptorOwner`; parent closes them after authenticated actor registration.
Child closes owner-pin copies through the existing exact FD allowlist before
exec. Ownership uses open-file-description queries, not slot/inode equality.
Close is idempotent, slot reuse is uncertain and unrelated replacement is not
closed. Loader owns reopened groups/executables and closes ledger in finally;
fixed entry, all partial-startup parent endpoints and journal custody remain
incomplete. Unsupported F_DUPFD_QUERY target has no fallback.

Native role credentials support reviewed equal five-set masks only. Root roles
carry ambient capabilities across ordinary exec with NOROOT locked and UID
automatic clearing enabled. Worker pre-exec retains only SETUID/SETGID/SETPCAP,
then its fixed setpriv vector clears groups/bounding/inheritable/ambient. The
controller continues through existing irreversible drop_controller before
untrusted import. None of these operations was run here. Complete actual
AppArmor BASE/ROLE/exec policy and supervisor containment remain S3 blockers.

The guard does not survive clone/exec automatically: child explicit rearm and
own-PID checks exist; the fixed post-exec entry must still create a new guard.
A process-local self-timer cannot replace independent lifetime supervision.
The trace provisioner is separate from confined actors, its map stays disabled,
and the partial syscall decoder always yields incomplete blocked evidence.

## Historical delivery — source 6a5d752, preserved record

Current source/test revision: `6a5d752412d7452008addcf93d78197322ecd157`.
Starting delivery: `e483307c3c5ea157068b59c192f6fb0dea27dd1b`.
**PARTIAL — EXACT SOURCE OR ENVIRONMENT BLOCKERS.** This specification describes
implemented primitives and the missing connected package, not a runnable probe.
The machine-readable register is `PROBE_A_NATIVE_COVERAGE.json`.

## Implemented source and disposition

| Component | Concrete source | Current limit |
|---|---|---|
| Activated-root boundary | `TrustedActorBootstrap.launch_integrated`, `IntegratedBootstrap.launch` | All activated-root preparation exceptions/interruption fail-stop; a valid attempt is claimed before factory preparation, with one-use claim handoff. Disabled/unprivileged calls remain harmless. Mandatory hard-deadline and all-exit storage wiring is still missing. |
| Independent audit reserve | `CleanupAuditAuthority`, `NativeReadCommands.for_audit`, `NativeBoundedCapture`, `NativeAtomicSpawner`, `ReviewedExecutionContract.before_spawn` | Actual server-side bootstrap identity grants the fixed read catalog until the original end; controller work remains cutoff-bounded. Incremental frames and audit-first turns prevent a stalled controller frame occupying the audit channel. External verifier/factory calls still need hard bounds. |
| Work/cleanup evidence separation | `EvidenceComposer`, `IndependentEvidenceAudit`, `IndependentSupervisor` | Missing work no longer requires invented success before cleanup. Nonzero guardian exit/interruption still attempts available audit. Invalid authorities stay quarantined. Partial package/journal APIs exist, but the native all-exit owner/persistence topology is incomplete. |
| Durable claim and cross-exec grant | `DurableAttemptLedger`, `NativeAttemptPermit`, `ExistingAttemptGrant` | SQLite exclusive claims, schema/inode checks, FULL/EXTRA durability, bounded contention, restart/replay rejection; v2 grant binds session/boot/source/inventory/policy/purpose/cutoff/end. Read-only grant validation never claims again. Fixture stores cannot grant native authority. Storage rollback is outside its guarantees. |
| Inventory collection/verification | `NativeAssetReader`, `elf_loading`, `collect_dependency_closure`, `PinnedSourceExport`, `NativeKernelFacts`, `construct_native_inventory`, `pinned_verifier` | No-follow retained directories/files, ordinary/alias target ancestry, inode substitution rejection, bounded ELF parsing and approved SONAME resolution. Existing OpenSSL 3 EVP verifies Ed25519. Dynamic Python/NSS/load behavior still requires actual runner acceptance. |
| Scope source | `NativeScopeObserver`, `provision_scopes`, `teardown_scopes` | Seven scopes, exact identities/ownership/ancestry, incarnation and population checks, separate gated provisioning/teardown. Nonempty native admission explicitly blocks missing independent pre-exec attachment trace; no fabricated atomic proof. |
| Allocation/service composition | `NativeActorAllocator`, `NativeRoleServiceAssembly` | Actual socketpair/memfd/pidfd allocation, fixed free config-FD slot, sealed identity, existing GuardianCore/FixedWorkload/ClientProcess/native adapter composition. Post-exec loader/descriptor reconstruction and guardian-observer channel handoff are missing. |
| Native policy primitive | `NativePolicyAdapter`, `socket_filter` | Uninstalled AppArmor exec-transition + x86_64 seccomp source, protocol-12 netfilter only for new root sockets; rejects new IP/Unix/packet routes, ptrace/process_vm/pidfd_getfd/io_uring/BPF bypasses. Complete profile assets, capability installation, mount/policy-package verification and supervisor confinement are missing. Netfilter/CAP_NET_ADMIN remains trusted privileged code, not kernel read-only authority. |
| Resources/journal/measurements | `NativeResourceCollector`, `UnsignedObservationJournal`, `SignedJournalCollector`, `validate_network_measurement`, `validate_cleanup_measurement` | Fixed bounded proc/listener/resolver reads, corruption-detecting partial journal, external signature adapter, DNS transaction/loopback/reject measurement schemas and typed counters. Kernel trace loader, complete cleanup/emergency schema/collector and external final owner are missing. Signed booleans and case strings cannot fill these gaps. |
| Hard deadline source | `probe_a_deadline_guard.c`, `NativeDeadlineGuard` | Monotonic POSIX signal timer with async-signal-safe `_exit(76)`; no root threads/Python signal timeout. Syntax tested only; authenticated artifact and every critical callback/entry boundary are not wired. Kernel uninterruptible sleep/runner destruction can still leave uncertainty. |

## Actual intended topology and authority

The three actor processes are guardian, observer and controller. Worker and
root peer incarnations are created only through fixed contained capture; read
and guardian command helpers use their separate scopes. These are **seven
child scopes**, not seven extra long-lived services.

| Owner/role | Descriptors and authority |
|---|---|
| Bootstrap/supervisor | Root identity/incarnation, exact source/export/interpreter; owns child pidfds, seven group FDs, temporary config writers/readers, private startup and observer-audit endpoints, durable claim and partial journal. Successful launch returns only to trusted supervisor control. Separate runner-owned containment, final capability reduction, deadline and external observation of its own exit are still missing source integration. |
| Guardian | Sealed config, startup/controller IPC; opens only reviewed command/group FDs after exec. Owns mutation/emergency journals, worker/peer stop and owned cleanup. It needs a new authenticated independent observer UID-audit handoff; current config does not provide it. It cannot attest its own disappearance. |
| Observer | Sealed config, distinct startup/controller/audit IPC. Controller and bootstrap audit executors have separate server-side purposes. Actual kernel/resource collection and externally configured signing/verification boundary must remain independent of guardian messages. It cannot attest its own shutdown. |
| Controller | Sealed config, startup/guardian/observer IPC and retained guardian/observer/bootstrap pidfds. UID/GID 65534, no groups/capabilities, NNP=1; no privileged metadata introspection. Controller import occurs only after the irreversible fixed drop. |
| Worker/peer | Separate atomic scopes, fixed argv, no actor/config/group descriptors. Worker final numeric UID/GID and empty caps/groups; root peer fixed loopback behavior. Detached descendants are accounted through scope population, never numeric PID trees. |
| Read/guardian commands | Fixed full argv, own respective scopes, no inherited actor endpoints. Read-only RPC limits the request interface; root/CAP_NET_ADMIN is not kernel read-only privilege. |

All contexts retain the same absolute end and a 60-second cleanup reserve.
A kill, successful command, process exit or signed assertion is not proof of
cleanup. At final expiry no fresh privileged observation/mutation is added to
obtain a better result. Root controller/observer shutdown attempts include their
owned descendants; guardian is not blindly killed during its cleanup reserve.

## Exact remaining source and dependency blockers

1. **S1 — NATIVE_IMPLEMENTATION_MISSING:** source-pinned post-exec entry/package
   loader, trusted grant/inventory/policy reconstruction, exact socket/descriptor
   ownership evidence and complete allocation disposal. No native entry script
   exists for the reviewed `--sealed-config-fd` vectors.
2. **S2 — SOURCE_DEFECT:** guardian configuration lacks the independent observer
   UID-audit endpoint/identity handoff required by `NativeRoleServiceAssembly`.
   A guardian-local read or injected success callback is not an acceptable fix.
3. **S3 — NATIVE_IMPLEMENTATION_MISSING:** complete AppArmor policy assets,
   authenticated installed-policy/mount inspector, role capability/group
   installation and bootstrap/supervisor containment/lifetime wiring. Signed
   profiles cannot grant SYS_ADMIN or excess role capabilities; current native
   policy code does not install the required final capability sets.
4. **S4 — NATIVE_IMPLEMENTATION_MISSING / REQUIRED_DEPENDENCY_UNAVAILABLE:**
   kernel socket/netfilter/pre-exec attachment measurement program and loader,
   actual event-to-incarnation/socket/counter correlation and decoder. Existing
   libbpf is discoverable; clang is unavailable. No packages may be installed,
   and no approved runner BTF/hook ABI or compiled reviewed trace asset exists.
5. **S5 — NATIVE_IMPLEMENTATION_MISSING:** complete owned-resource/emergency
   mutation measurement schema and collectors, signed independent journal
   production boundary and legitimate external owner of final supervisor exit/
   residual absence. Current kernel cleanup admission explicitly blocks them.
6. **S6 — SOURCE_DEFECT:** mandatory C guard around every potentially blocking
   verification/factory/collection/cleanup call and every root entry boundary;
   durable partial-package storage on outer/pre-service failure and all exits.
   The primitive and optional persistence calls exist, not the complete wiring.

These are source omissions. They are not relabelled as missing signatures or
unexecuted Linux acceptance. Remaining optional public-key/configuration inputs
are a separate external gate after this source work is completed.

## Manifest and approval workflow — unexecuted

After source completion and independent review, an approved immutable runner
collector may record actual protected files/parent identities, aliases, loader,
Python runtime, libcap/libc/NSS and transitive/configuration dependencies using
these readers. Static ELF edges do not prove dynamic imports or NSS behavior.
Approved SONAME and RPATH/RUNPATH resolution must be explicit; no `ldd`/target
execution or host search fallback. Include newly executed factory/verifier/
policy/guard/trace assets. Collect source exports after the immutable Git commit
and outside Git; neither a commit nor manifest includes its own hash.

Produce an unsigned candidate first. An external reviewer supplies trust roots
and genuine source/inventory/feature/policy signatures, then separate provisioning
permission. Actual scope inodes are observed after separately authorized
provisioning. A distinct v2 activation/attempt record is externally approved and
claimed durably once. Helpers validate that existing grant; they do not claim it
again and never receive approval-signing keys. No genuine manifest, key,
signature, provisioning or attempt was produced in this task.

## Future Linux falsification scenarios — NOT EXECUTED

- Kill/interruption at import, factory/property/constructor, partial allocation,
  clone return, sealing, capability drop, exec and readiness boundaries. No
  arbitrary Python may regain root; stale/missing grant never starts work.
- Verify actual atomically attached incarnation before first untrusted
  instruction; detached descendants remain in exact owned nondelegated scopes.
  Wrong ancestry/ownership, stale pidfds or migration fallback must block.
- Authenticate source, parent/alias/config/library/FD identities around reads;
  same bytes in a changed inode, altered NSS, unexpected dependency or wrong
  external signature must poison activation permanently.
- Independently verify guardian/observer RUNNING and baseline before controller
  release. Flood, partial/stalled frames and eight-second slow reads must leave
  audit capacity in the original cleanup reserve. No new work at cutoff and
  no privileged operation after final end.
- Demonstrate positive UDP/TCP DNS transaction and established loopback exchange
  using independent kernel/socket data. Denials require correlated firewall
  rejection, not timeout/unreachable or worker text; counters must bind exact
  family/chain/index/interval and reject resets/replays.
- Cancel before/during setup/case/cleanup; nonzero guardian exit, observer loss,
  supervisor failure, uncertain firewall write and deny-barrier failure must
  preserve failed work plus independently available cleanup observations.
- Verify owned-only IPv4/IPv6 restoration, worker/peer termination, guardian
  reaping, observer shutdown and external observation of supervisor/resources
  absence. SIGKILL, destroyed runner or lost kernel access may yield explicit
  incomplete/uncertain cleanup; never a trusted PASS.

Probe A execution: UNAUTHORIZED / NOT EXECUTED.
Trusted runtime PASS: UNAVAILABLE.
HAOS/Supervisor acceptance: NO-GO.
Production: NO-GO.
