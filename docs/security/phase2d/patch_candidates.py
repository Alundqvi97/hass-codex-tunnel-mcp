"""Deterministic review-only patch builder for upstream ha-mcp v8.6.0.

Executes only in disposable upstream checkout. Refuses unpinned source, verifies
Git blob hashes and exact context, and never reads production configuration.
Usage: python docs/security/phase2d/patch_candidates.py POLICY_OR_LOG [--apply]
The test workflow records conventional git diff and verifies git apply -R.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

UPSTREAM = "fc54437a804858732e4bc927add98e202d879a09"
FILES = {
    "policy": ("src/ha_mcp/server.py", "bf848dcec8345eba603295933768fca6724c913b"),
    "logging": ("homeassistant-addon/start.py", "88e926a59f568dc9a9bf7bcd719b518b42f52baa"),
}


def replace_exact(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"PATCH_CONTEXT_MISMATCH: expected 1 occurrence, got {count}")
    return text.replace(old, new, 1)


def policy_patch(s: str) -> str:
    s = replace_exact(s, "import logging\nfrom pathlib import Path", "import logging\nimport os\nfrom pathlib import Path")
    s = replace_exact(
        s,
        "        self._apply_tool_security_policies()\n",
        """        try:
            self._apply_tool_security_policies()
        except Exception:
            # Guard the entire server construction path, including errors
            # raised before the optional middleware constructor is reached.
            logger.error("Required policy initialization failed; MCP is not serving")
            raise RuntimeError("Required MCP policy initialization failed") from None
""",
    )
    s = replace_exact(
        s,
        "        # One-time ANY-match schema migration (PR #1993) runs even when",
        """        strict_value = os.environ.get("HA_MCP_REQUIRE_STRICT_POLICY", "").strip().lower()
        if strict_value not in {"", "0", "false", "no", "1", "true", "yes"}:
            raise RuntimeError("Invalid mandatory MCP policy setting")
        strict = strict_value in {"1", "true", "yes"}

        # One-time ANY-match schema migration (PR #1993) runs even when""",
    )
    s = replace_exact(
        s,
        "        if not self.settings.enable_tool_security_policies:\n            return\n\n        try:\n",
        """        if strict and not self.settings.enable_tool_security_policies:
            raise RuntimeError("Required MCP policy enforcement is disabled")
        if not self.settings.enable_tool_security_policies:
            return

        try:
""",
    )
    s = replace_exact(
        s,
        """        except Exception:
            logger.error(
                "tool_policy.json ANY-match migration failed; continuing. The """,
        """        except Exception:
            if strict:
                logger.error("Required MCP policy migration failed; refusing startup")
                raise RuntimeError("Required MCP policy migration failed") from None
            logger.error(
                "tool_policy.json ANY-match migration failed; continuing. The """,
    )
    s = replace_exact(
        s,
        """        except ImportError:
            logger.exception(
                "Tool Security Policies enabled (ENABLE_TOOL_SECURITY_POLICIES=true) "
                "but the policy package failed to import. TOOL SECURITY GATING IS NOT ACTIVE; "
                "all tool calls pass through ungated. Verify ha_mcp.policy is importable."
            )
            return
""",
        """        except ImportError:
            logger.error("Required MCP policy middleware unavailable; refusing startup")
            raise RuntimeError("Required MCP policy middleware unavailable") from None
""",
    )
    s = replace_exact(
        s,
        """        data_dir = get_data_dir()

        def _policy_provider() -> Policy:
""",
        """        data_dir = get_data_dir()

        def _policy_provider() -> Policy:
""",
    )
    s = replace_exact(
        s,
        """            return load_policy(data_dir)

        async def _approval_ws_client() -> Any:
""",
        """            policy = load_policy(data_dir)
            if strict:
                from .policy.persistence import POLICY_FILENAME

                if (
                    not (data_dir / POLICY_FILENAME).is_file()
                    or policy.rule_effect != "allow"
                    or not policy.rules
                    or any(rule.tool_name == "*" and not rule.when
                           for rule in policy.rules)
                ):
                    raise ValueError("Strict MCP policy requires a bounded allow list")
            return policy

        if strict:
            try:
                _policy_provider()
            except (ValueError, OSError):
                logger.error("Strict MCP policy unavailable or invalid; refusing startup")
                raise RuntimeError("Strict MCP policy unavailable or invalid") from None

        async def _approval_ws_client() -> Any:
""",
    )
    s = replace_exact(
        s,
        """        except Exception:
            logger.exception(
                "Failed to register PolicyMiddleware (data_dir=%s, "
                "ENABLE_TOOL_SECURITY_POLICIES=true). TOOL SECURITY GATING IS NOT ACTIVE; "
                "all tool calls pass through ungated.",
                data_dir,
            )
""",
        """        except Exception:
            logger.error("Required MCP policy middleware registration failed; refusing startup")
            raise RuntimeError("Required MCP policy middleware registration failed") from None
""",
    )
    return s


def logging_patch(s: str) -> str:
    s = replace_exact(s, "import urllib.request\nfrom datetime import datetime", "import urllib.request\nfrom urllib.parse import quote\nfrom datetime import datetime")
    key = "def log_info(message: str) -> None:"
    s = replace_exact(
        s, key,
        '''def install_secret_path_log_filter(secret_path: str) -> None:
    """Redact the configured endpoint credential from existing logging handlers.

    Handler filters cover standard logging, but not direct subprocess writes to
    stderr or third-party handlers created after installation. These must be
    covered separately before any Supervisor deployment.
    """
    import logging

    variants = {
        secret_path,
        quote(secret_path, safe=""),
        secret_path.replace("/", "\\\\/"),
    }

    class SecretPathFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            value = record.getMessage()
            for variant in variants:
                if variant:
                    value = value.replace(variant, "[MCP_SECRET_REDACTED]")
            record.msg = value
            record.args = ()
            return True

    filter_instance = SecretPathFilter()
    for name in ("", "fastmcp", "uvicorn", "uvicorn.error", "uvicorn.access"):
        for handler in logging.getLogger(name).handlers:
            handler.addFilter(filter_instance)


'''+key
    )
    s = replace_exact(
        s,'f"Custom secret path is invalid ({path!r}), ignoring. {_SECRET_PATH_HINT}"',
        'f"Custom secret path is invalid; ignoring. {_SECRET_PATH_HINT}"'
    )
    s = replace_exact(s,'f"Stored secret path is invalid ({stored_path!r}), regenerating. {_SECRET_PATH_HINT}"',
                       'f"Stored secret path is invalid; regenerating. {_SECRET_PATH_HINT}"')
    s = replace_exact(s,'log_error(f"Failed to read stored secret path: {e}")',
                      'log_error("Failed to read stored secret path (details withheld)")')
    s = replace_exact(s,'log_error(f"Failed to save secret path: {e}")',
                      'log_error("Failed to save secret path (details withheld)")')
    s = replace_exact(
        s,
        '''    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        detail = (
            f"HTTP {e.code}: {e.reason}"
            if isinstance(e, urllib.error.HTTPError)
            else str(e)
        )
        log_error(
            f"Failed to persist secret_path to addon options ({detail}). "
            f"This addon will still run with secret_path={secret_path!r}, "
            "but other addons (e.g. the webhook proxy) cannot auto-discover "
            "it via Supervisor. Workaround: open this addon's Configuration "
            "tab and paste the secret_path above into the 'Secret path override' "
            "field, then save."
        )
''',
        '''    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        log_error(
            "Failed to persist secret path to add-on options (details withheld). "
            "MCP remains configured; an administrator can inspect the add-on "
            "Configuration tab for the saved path and repair the options."
        )
'''
    )
    s = replace_exact(
        s,
        '''        # Top-level crash handler: intentionally catch ANY exit (including
        # SystemExit, translated to its code below) so the add-on supervisor
        # always sees a clean process exit code instead of a traceback.
        import traceback

        log_error(f"MCP server crashed: {e}")
        traceback.print_exc(file=sys.stderr)
        # Log the root cause if this exception was chained
        cause = e.__cause__ or e.__context__
        if cause:
            log_error(f"Caused by: {cause}")
            traceback.print_exception(
                type(cause), cause, cause.__traceback__, file=sys.stderr
            )
''',
        '''        # Do not log exception text or traceback: third-party HTTP errors
        # can embed the path capability or its escaped representation.
        log_error(f"MCP server stopped ({type(e).__name__}); details withheld")
'''
    )
    s = replace_exact(
        s,
        '''    log_info(f"🔐 MCP Server URL: http://<home-assistant-ip>:9583{secret_path}")
    log_info("")
    log_info(f"   Secret Path: {secret_path}")
    log_info("")
    log_info("   ⚠️  IMPORTANT: Copy this exact URL - the secret path is required!")
    log_info("   💡 This path is auto-generated and persisted to /data/secret_path.txt")
''',
        '''    log_info("MCP endpoint configured; secret path withheld from logs")
    log_info("")
    log_info("Retrieve the path through the authenticated add-on Configuration tab")
    log_info("The path is persisted in the add-on data directory")
'''
    )
    s = replace_exact(
        s,
        '''    install_sdk_log_filters()

    # fastmcp's DNS-rebinding guard''',
        '''    install_sdk_log_filters()
    install_secret_path_log_filter(secret_path)

    # fastmcp's DNS-rebinding guard'''
    )
    return s


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", choices=FILES)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--root", type=Path, default=Path("ha_mcp_pinned"))
    args = parser.parse_args()
    root = args.root.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=5
    ).strip()
    if revision != UPSTREAM:
        raise RuntimeError("SOURCE_REVISION_MISMATCH")
    target, baseline = FILES[args.candidate]
    path = root / target
    actual = subprocess.check_output(
        ["git", "-C", str(root), "hash-object", target], text=True, timeout=5
    ).strip()
    if actual != baseline:
        raise RuntimeError("SOURCE_BLOB_MISMATCH")
    content = path.read_text(encoding="utf-8")
    transformed = (policy_patch if args.candidate == "policy" else logging_patch)(content)
    if transformed == content:
        raise RuntimeError("EMPTY_CHANGE")
    if args.apply:
        path.write_text(transformed, encoding="utf-8")
    print(f"{args.candidate}: pinned baseline and contexts verified, apply={args.apply}")


if __name__ == "__main__":
    main()
