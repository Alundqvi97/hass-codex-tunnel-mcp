#!/usr/bin/env bash
set -euo pipefail

# Disabled native Core administrator development plus retained offline security. Never run live Probe A, root,
# sudo, capability changes, firewall/cgroup mutation, VMs, QEMU, production,
# tunnel connections, paid services, workflow activation, commits or publication.
# No application/security/workflow/lockfile/production edits during setup.
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
setup_dir=${ADMIN_DEV_STATE:-/workspace/.development/hass-codex-tunnel-mcp}
approved=14fca17f54f364019b6bfa9074d1e016ccb6f92b
upstream=fc54437a804858732e4bc927add98e202d879a09
fixture_cache="$setup_dir/fixtures/ha-mcp.git"
security_python="$setup_dir/security-venv/bin/python"
uv_cache="$setup_dir/uv-cache"
mode=${1:---setup}
python3 -B - "$repo_dir" "$setup_dir" "${ADMIN_NATIVE_STATE:-$setup_dir/native}" <<'PY_STATE'
from pathlib import Path
import sys
repo = Path(sys.argv[1]).resolve()
for value in sys.argv[2:]:
    if value and Path(value).resolve().is_relative_to(repo):
        raise SystemExit("BLOCKED: development state must stay outside the checkout")
PY_STATE

fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || fail "Root execution is prohibited; use the ordinary cloud user."

check_base() {
    local target="$1" head branch
    [ -d "$target" ] && [ ! -L "$target" ] || fail "Missing or symlink checkout: $target"
    head=$(git -C "$target" rev-parse --verify 'HEAD^{commit}') || fail "Unreadable Git HEAD."
    branch=$(git -C "$target" branch --show-current)
    case "$branch" in main|master) fail "Checkout is on $branch; safely select the approved PR #2 baseline first." ;; esac
    git -C "$target" cat-file -e "$approved^{commit}" ||
        fail "Reviewed native source commit is missing; do not engineer from main."
    git -C "$target" merge-base --is-ancestor "$approved" "$head" ||
        fail "HEAD does not descend from reviewed PR #2 source $approved."
    # Check origin identity without printing credentials or changing the remote.
    python3 -B - "$target" <<'PY'
import subprocess, sys
from urllib.parse import urlsplit
remote = subprocess.check_output(["git", "-C", sys.argv[1], "remote", "get-url", "origin"], text=True).strip()
if "://" in remote:
    value = urlsplit(remote)
    host, path = value.hostname, value.path.lstrip("/")
elif ":" in remote and "@" in remote.split(":", 1)[0]:
    authority, path = remote.split(":", 1)
    host = authority.rsplit("@", 1)[-1]
else:
    raise SystemExit("BLOCKED: origin is not an unambiguous GitHub repository.")
if (host, path.removesuffix(".git")) != ("github.com", "Alundqvi97/hass-codex-tunnel-mcp"):
    raise SystemExit("BLOCKED: wrong repository identity.")
PY
    local required
    for required in custom_components/hass_codex_admin/engine.py \
        custom_components/hass_codex_admin/connector.py \
        requirements/admin-test.lock.txt \
        .github/workflows/phase2l-offline-only.yml \
        docs/security/phase2l/probe_a_runner.py \
        docs/security/phase2l/probe_a_privilege.py \
        docs/security/phase2l/probe_a_os_boundary.py \
        docs/security/phase2l/probe_a_observer.py \
        docs/security/phase2l/probe_a_containment.py \
        docs/security/phase2l/probe_a_attestation.py \
        docs/security/phase2l/probe_a_guardian.py \
        tests/offline/test_phase2l_probe_a_s1_s3.py; do
        [ -f "$target/$required" ] && [ ! -L "$target/$required" ] ||
            fail "Required security module/workflow is missing or symlinked: $required"
    done
    python3 -B - "$target/.github/workflows/phase2l-offline-only.yml" "$upstream" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
if ("ref: " + sys.argv[2]) not in text or "test_phase2l_*.py" not in text:
    raise SystemExit("BLOCKED: authoritative Phase 2L workflow no longer matches this setup; review it.")
PY
    printf 'PR #2 base verified: HEAD=%s branch=%s approved=%s\n' "$head" "${branch:-detached}" "$approved"
}

case "$mode" in
    --check-base)
        [ "$#" -le 2 ] || fail "Usage: install.sh --check-base [checkout]"
        check_base "${2:-$repo_dir}"
        exit 0 ;;
    --setup|--verify) [ "$#" -le 1 ] || fail "Unexpected arguments." ;;
    *) fail "Use --setup (default), --verify (offline), or --check-base." ;;
esac
# Every setup/validation starts with identity, HEAD, ancestry and module checks.
# This script never resets, stashes, cleans, commits, or switches the checkout.
check_base "$repo_dir"

if [ "$mode" = --setup ]; then
    command -v uv >/dev/null || fail "The supplied uv tool is unavailable."
    mkdir -p "$setup_dir" "$uv_cache" "$setup_dir/fixtures"
    if [ ! -x "$security_python" ]; then
        [ ! -e "$setup_dir/security-venv" ] || fail "Preserve existing incomplete security-venv; diagnose it first."
        uv --cache-dir "$uv_cache" venv --python python3 "$setup_dir/security-venv"
    fi
    # Reuse verified pytest when present. This is the existing CI range, not a new pin.
    # Prefer the retained package cache; fetch with normal TLS verification only if needed.
    if ! "$security_python" -B -c 'import pytest; from importlib.metadata import version; assert 8 <= int(version("pytest").split(".")[0]) < 10' >/dev/null 2>&1; then
        uv --cache-dir "$uv_cache" --offline pip install \
            --python "$security_python" 'pytest>=8,<10' ||
        uv --cache-dir "$uv_cache" --system-certs pip install \
            --python "$security_python" 'pytest>=8,<10'
    fi
    uv --cache-dir "$uv_cache" pip check --python "$security_python"

    # This bare repository is a dependency/test-fixture cache, not another project checkout.
    # Keep it pristine; candidate patches are applied ONLY to disposable validation copies.
    if [ ! -e "$fixture_cache" ]; then
        git init --bare --initial-branch=phase2l-fixture -q "$fixture_cache"
        git -C "$fixture_cache" remote add origin https://github.com/homeassistant-ai/ha-mcp.git
    fi
    [ "$(git -C "$fixture_cache" rev-parse --is-bare-repository)" = true ] ||
        fail "Fixture cache is not a bare repository; preserve it and investigate."
    if ! git -C "$fixture_cache" cat-file -e "$upstream^{commit}" 2>/dev/null; then
        git -C "$fixture_cache" fetch --no-tags --depth=1 \
            https://github.com/homeassistant-ai/ha-mcp.git "$upstream"
    fi
    if ! git -C "$fixture_cache" show-ref --verify --quiet refs/heads/phase2l-fixture; then
        git -C "$fixture_cache" update-ref refs/heads/phase2l-fixture "$upstream"
    fi
fi
[ -x "$security_python" ] || fail "Security test environment is missing; run --setup."
[ "$(git -C "$fixture_cache" rev-parse 'refs/heads/phase2l-fixture^{commit}')" = "$upstream" ] ||
    fail "Fixture ref does not match the authoritative upstream pin."
git -C "$fixture_cache" fsck --full

# Modern native administrator fixture. No permanent HA service or tunnel.
admin_setup=${ADMIN_NATIVE_STATE:-$setup_dir/native}
admin_python="$admin_setup/venv/bin/python"
if [ "$mode" = --setup ]; then
    export UV_PYTHON_INSTALL_DIR="$admin_setup/python"
    mkdir -p "$admin_setup/cache"
    if [ ! -x "$admin_python" ]; then
        [ ! -e "$admin_setup/venv" ] || fail "Preserve incomplete administrator venv and diagnose."
        if [ -z "${ADMIN_NATIVE_PYTHON:-}" ]; then
            uv --cache-dir "$admin_setup/cache" python install 3.14.2 --no-bin
        fi
        uv --cache-dir "$admin_setup/cache" venv --python "${ADMIN_NATIVE_PYTHON:-3.14.2}" "$admin_setup/venv"
    fi
    uv --cache-dir "$admin_setup/cache" pip sync --python "$admin_python" \
        --require-hashes "$repo_dir/requirements/admin-test.lock.txt"
    uv --cache-dir "$admin_setup/cache" pip check --python "$admin_python"
fi
[ -x "$admin_python" ] || fail "Native Core development environment missing; run --setup."
"$admin_python" -B -c 'import sys; from importlib.metadata import version; assert sys.version_info[:3] == (3,14,2); assert version("homeassistant") == "2026.10.0"; assert version("mcp") == "1.28.1"'
command -v node >/dev/null || fail "Supplied node tool is required for approval panel syntax."

# --verify performs no dependency download, external service request, or OS mutation.
# Generated candidate files, bytecode, test fixtures and logs stay outside the checkout.
run_dir=$(mktemp -d /tmp/native-admin-validation.XXXXXX)
export TMPDIR="$run_dir/tmp"
export PYTHONPYCACHEPREFIX="$setup_dir/security-pycache"
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
mkdir -p "$TMPDIR" "$PYTHONPYCACHEPREFIX"
cd "$repo_dir"
git status --porcelain=v1 --untracked-files=all --ignored > "$run_dir/status.before"
git diff --binary > "$run_dir/worktree.before"
git diff --cached --binary > "$run_dir/index.before"

# Primary connected workflow: actual disposable Core/native MCP and owner
# approval. Fixtures enforce loopback and remove only their own temporary data.
if "$admin_python" -B -m unittest discover -s tests/staging -p 'test_admin_product.py' -v \
    > "$run_dir/native-admin.log" 2>&1; then
    tail -5 "$run_dir/native-admin.log"
else
    test_status=$?
    cat "$run_dir/native-admin.log" >&2
    exit "$test_status"
fi
"$admin_python" -B -m py_compile custom_components/hass_codex_admin/*.py custom_components/hass_codex_tunnel_mcp/*.py tests/staging/*admin*.py
node --check custom_components/hass_codex_admin/panel.js
node --check tests/staging/admin_browser_fixture.cjs
if [ -n "${ADMIN_BROWSER_EXECUTABLE:-}" ]; then
    browser_state="$setup_dir/browser"
    if [ "$mode" = --setup ]; then
        mkdir -p "$browser_state"
        cp tests/staging/browser/package*.json "$browser_state/"
        PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm --cache "$setup_dir/npm-cache" ci \
            --prefix "$browser_state" --ignore-scripts --no-audit --no-fund
    fi
    NODE_PATH="$browser_state/node_modules${NODE_PATH:+:$NODE_PATH}" "$admin_python" -B -m unittest \
        discover -s tests/staging -p 'test_admin_browser.py' -v > "$run_dir/browser.log" 2>&1 || {
        cat "$run_dir/browser.log" >&2; exit 1;
    }
fi

# Reproduce .github/workflows/phase2l-offline-only.yml without workflow activation.
git clone -q --no-hardlinks --no-checkout "$fixture_cache" "$run_dir/ha_mcp_pinned"
git -C "$run_dir/ha_mcp_pinned" checkout --quiet --detach "$upstream"
test "$(git -C "$run_dir/ha_mcp_pinned" rev-parse HEAD)" = "$upstream"
python3 -B docs/security/phase2d/patch_candidates.py policy --root "$run_dir/ha_mcp_pinned" --apply
python3 -B docs/security/phase2d/patch_candidates.py logging --root "$run_dir/ha_mcp_pinned" --apply
python3 -B docs/security/phase2f/strict_addon_candidate.py --root "$run_dir/ha_mcp_pinned" --apply
python3 -B docs/security/phase2g/middleware_revalidation.py --root "$run_dir/ha_mcp_pinned" --apply
python3 -B docs/security/phase2k/source_candidate.py --root "$run_dir/ha_mcp_pinned" --apply
python3 -B docs/security/phase2l/stage_candidate.py \
    --source "$run_dir/ha_mcp_pinned" --destination "$run_dir/phase2l-candidate" \
    --reference docs/security/phase2k
git -C "$run_dir/ha_mcp_pinned" diff --check

if python3 -B -m unittest discover -s tests/offline -p 'test_phase2l_*.py' -v \
    > "$run_dir/phase2l.log" 2>&1; then
    python3 -B - "$run_dir/phase2l.log" <<'PY'
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text()
counts = re.findall(r"Ran (\d+) tests? in ", text)
if not counts or int(counts[-1]) < 266 or "(skipped=" in text or not re.search(r"^OK$", text, re.MULTILINE):
    raise SystemExit("BLOCKED: Phase 2L must execute at least 266 passing tests with no skips.")
print("\n".join(text.splitlines()[-5:]))
PY
else
    test_status=$?
    cat "$run_dir/phase2l.log" >&2
    exit "$test_status"
fi
python3 -B -m py_compile docs/security/phase2l/*.py
python3 -B -m compileall -q custom_components docs/security tests
# Parse only. Never execute the VM/guest runner.
bash -n docs/security/phase2h/runner_once.sh

# Nonprivileged regression scope from offline-security.yml; omit runtime staging.
# Enforce local-only test sockets and prevent incidental public DNS lookups.
# This temporary pytest plugin changes no application code or test assertions.
cat > "$run_dir/probe_offline_network.py" <<'PY'
import ipaddress
import socket

def _loopback(host):
    if isinstance(host, bytes):
        host = host.decode("ascii")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except (ValueError, TypeError):
        return False

def _check(sock, address):
    if sock.family == socket.AF_UNIX:
        return  # Local IPC; no external networking.
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        raise OSError("Offline validation forbids this socket family")
    if not isinstance(address, tuple) or not _loopback(address[0]):
        raise OSError("Offline validation forbids non-loopback socket operations")

_original_dns = socket.getaddrinfo
def _dns(host, *args, **kwargs):
    if not _loopback(host):
        raise OSError("Offline validation forbids non-loopback DNS")
    answers = _original_dns(host, *args, **kwargs)
    if any(not _loopback(answer[4][0]) for answer in answers):
        raise OSError("Offline validation rejects a non-loopback resolver result")
    return answers

def pytest_sessionstart(session):
    socket.getaddrinfo = _dns
    for name in ("connect", "connect_ex", "bind"):
        original = getattr(socket.socket, name)
        def guarded(self, address, *args, _original=original, **kwargs):
            _check(self, address)
            return _original(self, address, *args, **kwargs)
        setattr(socket.socket, name, guarded)
    original_sendto = socket.socket.sendto
    def sendto(self, data, *args):
        if args:
            _check(self, args[-1])
        return original_sendto(self, data, *args)
    socket.socket.sendto = sendto
PY
# Synthetic loopback HTTP fixtures/fake tunnel clients are permitted, no real tunnel.
PYTHONPATH="$run_dir${PYTHONPATH:+:$PYTHONPATH}" "$security_python" -B -m pytest \
    -p probe_offline_network -q -rs -p no:cacheprovider \
    --basetemp="$run_dir/pytest" --junitxml="$run_dir/regression.xml" \
    tests --ignore=tests/staging

git diff --check
git status --porcelain=v1 --untracked-files=all --ignored > "$run_dir/status.after"
git diff --binary > "$run_dir/worktree.after"
git diff --cached --binary > "$run_dir/index.after"
cmp "$run_dir/status.before" "$run_dir/status.after"
cmp "$run_dir/worktree.before" "$run_dir/worktree.after"
cmp "$run_dir/index.before" "$run_dir/index.after"
check_base "$repo_dir"
printf 'Offline validation completed; logs and generated fixtures: %s\n' "$run_dir"
printf 'No live Probe A/OS proof or runtime authorization follows from these results.\n'

