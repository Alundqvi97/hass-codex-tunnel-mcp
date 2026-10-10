"""Phase 2L future-only pre-guest guard. Never launches anything.

A consistent static plan still cannot authorize VM creation without
independent QEMU resolver-route AND kernel firewall evidence.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from network_preflight import inspect_network, load_manifest, before_guest_authorization

NETDEV = (
    "user,id=net0,ipv6=off,hostfwd=tcp:127.0.0.1:18123-:8123,"
    "hostfwd=tcp:127.0.0.1:18124-:80,"
    "hostfwd=tcp:127.0.0.1:14357-:4357,"
    "hostfwd=tcp:127.0.0.1:19583-:9583"
)

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument("--resolv-conf",type=Path,required=True)
    ap.add_argument("--manifest",type=Path,required=True)
    ap.add_argument("--guest-source",type=Path,required=True)
    args=ap.parse_args(argv)
    # This source check is not runtime QEMU attestation.
    try:
        guest=args.guest_source.read_text(encoding="utf-8")
        if "ipv6=off" not in guest or any(
            x not in guest for x in ("18123-:8123","18124-:80","14357-:4357","19583-:9583")
        ):
            print("PHASE2L_BLOCKED_QEMU_SOURCE_UNVERIFIED")
            return 3
        resolv=args.resolv_conf.read_text(encoding="utf-8")
    except OSError:
        print("PHASE2L_BLOCKED_RESOLVER_OR_GUEST_SOURCE_UNAVAILABLE")
        return 3
    try:
        manifest=load_manifest(args.manifest.read_text(encoding="utf-8"))
    except OSError:
        print("PHASE2L_BLOCKED_MANIFEST_UNAVAILABLE")
        return 3
    except ValueError:
        print("PHASE2L_BLOCKED_MALFORMED_MANIFEST")
        return 3
    outcome=inspect_network(resolv,manifest,NETDEV)
    if outcome.status!="OFFLINE_CONSISTENT_NOT_RUNTIME_VERIFIED":
        print(outcome.receipt())
        return 3
    # Approval for the original single experiment is consumed. A future
    # observer must be designed, reviewed and bound here, not just an env flag.
    final=before_guest_authorization(outcome)
    print(final.receipt())
    return 3

if __name__=="__main__":
    raise SystemExit(main())
