#!/usr/bin/env bash
# Phase 2H: single QEMU/HAOS guest; no production resources, artifacts or caches.
set -Eeuo pipefail
umask 077
WORK="$(mktemp -d /tmp/phase2h-single-vm.XXXXXXXX)"
export PHASE2H_WORK="$WORK"
GUEST_USER="phase2hvm"
GUEST_SEEDED=false
RULES_CONFIGURED=false
MOUNTED=false
NBD_CONNECTED=false
CLEANUP_COMPLETED=false

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  set +e
  sudo pkill -u "$GUEST_USER" qemu-system-x86_64 >/dev/null 2>&1 || true
  sleep 2
  if [[ "$MOUNTED" == true ]]; then sudo umount "$WORK/mount" >/dev/null 2>&1; fi
  if [[ "$NBD_CONNECTED" == true ]]; then sudo qemu-nbd --disconnect /dev/nbd0 >/dev/null 2>&1; fi
  if [[ "$RULES_CONFIGURED" == true ]]; then
    sudo iptables -w 5 -D OUTPUT -m owner --uid-owner "$GUEST_USER" -j PHASE2H_GUEST >/dev/null 2>&1
    sudo iptables -w 5 -F PHASE2H_GUEST >/dev/null 2>&1
    sudo iptables -w 5 -X PHASE2H_GUEST >/dev/null 2>&1
    sudo ip6tables -w 5 -D OUTPUT -m owner --uid-owner "$GUEST_USER" -j PHASE2H_GUEST6 >/dev/null 2>&1
    sudo ip6tables -w 5 -F PHASE2H_GUEST6 >/dev/null 2>&1
    sudo ip6tables -w 5 -X PHASE2H_GUEST6 >/dev/null 2>&1
  fi
  [[ -z "$(pgrep -u "$GUEST_USER" qemu-system-x86_64 2>/dev/null)" ]] && echo "PHASE2H_GUEST_PROCESS_CLEANUP=PASS" || echo "PHASE2H_GUEST_PROCESS_CLEANUP=NOT_VERIFIED"
  sudo setfacl -x "u:$GUEST_USER" /dev/kvm >/dev/null 2>&1 || true
  sudo userdel "$GUEST_USER" >/dev/null 2>&1 || true
  sudo rm -rf -- "$WORK"
  [[ ! -e "$WORK" ]] && echo "PHASE2H_TEMPORARY_VM_FILES_REMOVED=PASS" || echo "PHASE2H_TEMPORARY_VM_FILES_REMOVED=FAIL"
  echo "PHASE2H_PUBLIC_ARTIFACT_OR_CACHE_UPLOAD=NONE"
  echo "PHASE2H_EXIT_STATUS=$exit_code"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "${GITHUB_REPOSITORY:-}" == "Alundqvi97/hass-codex-tunnel-mcp" ]]
[[ "${GITHUB_REF:-}" == "refs/heads/security/ha-mcp-phase2d-candidates" ]]
[[ "${RUNNER_OS:-}" == "Linux" ]]
[[ "${ImageOS:-}" == "ubuntu24" || "${ImageOS:-}" == "ubuntu24.04" || "${ImageOS:-}" == "ubuntu24.04.0" || "${ImageOS:-}" == ubuntu24* ]]
echo "PHASE2H_RUNNER=STANDARD_UBUNTU_24_04"
python3 - <<'PY'
import json,urllib.request,os
url="https://api.github.com/repos/Alundqvi97/hass-codex-tunnel-mcp"
with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"phase2h-gated-test"}),timeout=15) as r: a=json.load(r)
assert a["private"] is False and a["visibility"]=="public"
url="https://api.github.com/repos/home-assistant/operating-system/releases/tags/18.3"
with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"phase2h-gated-test"}),timeout=15) as r: a=json.load(r)
asset=next(x for x in a["assets"] if x["name"]=="haos_ova-18.3.qcow2.xz")
assert asset["digest"]=="sha256:fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090"
assert asset["size"]==510014132
assert asset["browser_download_url"]=="https://github.com/home-assistant/operating-system/releases/download/18.3/haos_ova-18.3.qcow2.xz"
print("PHASE2H_REPOSITORY_PUBLIC=PASS")
print("PHASE2H_OFFICIAL_IMAGE_DIGEST_METADATA=PASS")
print("PHASE2H_PAID_RUNNER_OR_ARTIFACT=NONE")
PY

AVAILABLE_KIB="$(df -Pk "$WORK" | awk 'NR==2 {print $4}')"
TOTAL_KIB="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
[[ "$AVAILABLE_KIB" -ge 15000000 && "$TOTAL_KIB" -ge 12000000 && "$(nproc)" -ge 4 ]] || { echo "PHASE2H_RESOURCE_GATE=BLOCKED"; exit 3; }
echo "PHASE2H_RESOURCE_GATE=PASS"

# Trusted Ubuntu repository dependencies only, on ephemeral runner.
sudo apt-get update -qq >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends qemu-system-x86 qemu-utils ovmf acl xz-utils iptables >/dev/null
command -v qemu-system-x86_64 >/dev/null
command -v qemu-nbd >/dev/null
test -r /usr/share/OVMF/OVMF_CODE.fd

sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$GUEST_USER"
test -e /dev/kvm || { echo "PHASE2H_KVM_DEVICE=BLOCKED"; exit 4; }
sudo setfacl -m "u:$GUEST_USER:rw" /dev/kvm
if ! sudo -u "$GUEST_USER" test -r /dev/kvm || ! sudo -u "$GUEST_USER" test -w /dev/kvm; then
  echo "PHASE2H_KVM_PERMISSIONS=BLOCKED"
  exit 4
fi
echo "PHASE2H_KVM_ACCESS_PERMISSION=PASS"

# Guest egress isolation enforced by owner-specific host firewall chains.
# No bridged adapter. Only public IPv4 HTTPS/HTTP, DNS and NTP egress.
# RFC1918, loopback, link-local, multicast, IPv6 and all other ports denied.
sudo iptables -w 5 -N PHASE2H_GUEST
sudo ip6tables -w 5 -N PHASE2H_GUEST6
RULES_CONFIGURED=true
sudo iptables -w 5 -I OUTPUT 1 -m owner --uid-owner "$GUEST_USER" -j PHASE2H_GUEST
sudo ip6tables -w 5 -I OUTPUT 1 -m owner --uid-owner "$GUEST_USER" -j PHASE2H_GUEST6
for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
  sudo iptables -w 5 -A PHASE2H_GUEST -d "$cidr" -j REJECT
done
sudo iptables -w 5 -A PHASE2H_GUEST -p tcp -m multiport --dports 80,443 -j ACCEPT
sudo iptables -w 5 -A PHASE2H_GUEST -p udp -m multiport --dports 53,123 -j ACCEPT
sudo iptables -w 5 -A PHASE2H_GUEST -j REJECT
sudo ip6tables -w 5 -A PHASE2H_GUEST6 -j REJECT
echo "PHASE2H_GUEST_NETWORK=USER_MODE_NAT_PUBLIC_WEB_DNS_NTP_ONLY"
echo "PHASE2H_PRIVATE_AND_IPV6_EGRESS=BLOCKED"

# Exact upstream source; review candidates are applied only to this checkout.
test "$(git -C ha_mcp_pinned rev-parse HEAD)" = fc54437a804858732e4bc927add98e202d879a09
python3 docs/security/phase2d/patch_candidates.py policy --apply >/dev/null
python3 docs/security/phase2d/patch_candidates.py logging --apply >/dev/null
python3 docs/security/phase2f/strict_addon_candidate.py --apply >/dev/null
python3 docs/security/phase2g/middleware_revalidation.py --apply >/dev/null
git -C ha_mcp_pinned diff --check
echo "PHASE2H_REVIEWED_PATCH_APPLICATION=PASS"

# Download exactly one official image; verify digest before decompressing.
curl --fail --location --silent --show-error --retry 2 --connect-timeout 25 --max-time 300 \
  "https://github.com/home-assistant/operating-system/releases/download/18.3/haos_ova-18.3.qcow2.xz" \
  -o "$WORK/haos_ova-18.3.qcow2.xz"
printf '%s  %s\n' fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090 "$WORK/haos_ova-18.3.qcow2.xz" | sha256sum -c - >/dev/null
echo "PHASE2H_DOWNLOADED_IMAGE_SHA256=PASS"
xz --decompress "$WORK/haos_ova-18.3.qcow2.xz"
qemu-img check "$WORK/haos_ova-18.3.qcow2" >/dev/null
qemu-img resize "$WORK/haos_ova-18.3.qcow2" 32G >/dev/null

# Stage source/positive policy into the guest's Supervisor local add-on tree
# using kernel NBD only (not a second libguestfs helper VM).
mkdir -p "$WORK/addon" "$WORK/mount"
cp ha_mcp_pinned/homeassistant-addon/{config.yaml,Dockerfile,start.py} "$WORK/addon/"
cp ha_mcp_pinned/{pyproject.toml,uv.lock} "$WORK/addon/"
cp -a ha_mcp_pinned/src "$WORK/addon/"
python3 - "$WORK/addon" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
cfg=p/"config.yaml"
s=cfg.read_text()
assert '  require_strict_tool_policy: false' in s and '  require_strict_tool_policy: bool?' in s
s=s.replace('slug: "ha_mcp"', 'slug: "ha_mcp_phase2h"')
s=s.replace('version: "8.5.0"','version: "8.6.0"')
s=s.replace('name: "Home Assistant MCP Server"','name: "Phase2H Synthetic MCP"')
s="\n".join(x for x in s.split("\n") if not x.startswith("image:"))
cfg.write_text(s)
d=p/"Dockerfile"
s=d.read_text()
assert "COPY homeassistant-addon/start.py /" in s
d.write_text(s.replace("COPY homeassistant-addon/start.py /","COPY start.py /"))
PY
if sudo modprobe nbd max_part=16 2>/dev/null && test -b /dev/nbd0 && sudo qemu-nbd --connect=/dev/nbd0 "$WORK/haos_ova-18.3.qcow2" >/dev/null 2>&1; then
  NBD_CONNECTED=true
  sudo udevadm settle >/dev/null 2>&1 || true
  if test -b /dev/nbd0p8 && sudo mount /dev/nbd0p8 "$WORK/mount" >/dev/null 2>&1; then
    MOUNTED=true
    sudo mkdir -p "$WORK/mount/supervisor/addons/local/ha_mcp_phase2h" "$WORK/mount/supervisor/addons/data/local_ha_mcp_phase2h"
    sudo cp -a "$WORK/addon/." "$WORK/mount/supervisor/addons/local/ha_mcp_phase2h/"
    printf '%s\n' '{"schema_version":2,"rule_effect":"allow","rules":[{"tool_name":"ha_get_overview","when":[],"remember_minutes":0}]}' | sudo tee "$WORK/mount/supervisor/addons/data/local_ha_mcp_phase2h/tool_policy.json" >/dev/null
    sudo chmod 0600 "$WORK/mount/supervisor/addons/data/local_ha_mcp_phase2h/tool_policy.json"
    sudo umount "$WORK/mount"
    MOUNTED=false
    GUEST_SEEDED=true
  fi
  sudo qemu-nbd --disconnect /dev/nbd0 >/dev/null 2>&1 || true
  NBD_CONNECTED=false
fi
export PHASE2H_LOCAL_ADDON_SEEDED="$GUEST_SEEDED"
echo "PHASE2H_SUPERVISOR_LOCAL_ADDON_SOURCE_SEEDED=$GUEST_SEEDED"
sudo chown "$GUEST_USER:$GUEST_USER" "$WORK/haos_ova-18.3.qcow2"
chmod 755 "$WORK"
sudo touch "$WORK/serial-private.log"
sudo chown "$GUEST_USER:$GUEST_USER" "$WORK/serial-private.log"
echo "PHASE2H_VM_GUEST_LIMIT=ONE"
# If a filesystem quota is hit, stop this guest; no retry on another host.
(
  while true; do
    sleep 20
    [[ -d "$WORK" ]] || break
    amount="$(du -sk "$WORK/haos_ova-18.3.qcow2" 2>/dev/null | awk '{print $1}')"
    if [[ "${amount:-0}" -gt 11500000 ]]; then
      echo "PHASE2H_SPARSE_DISK_BOUND_EXCEEDED=BLOCKED"
      sudo pkill -u "$GUEST_USER" qemu-system-x86_64 || true
      break
    fi
  done
) &
WATCH_PID="$!"
set +e
timeout --signal=TERM --kill-after=20s 2040s python3 docs/security/phase2h/single_haos_guest.py
result="$?"
set -e
kill "$WATCH_PID" >/dev/null 2>&1 || true
wait "$WATCH_PID" >/dev/null 2>&1 || true
echo "PHASE2H_SINGLE_VM_RUN_EXIT=$result"
exit "$result"
