#!/usr/bin/env python3
"""Validate one Agent POST /v1/trace response as an independent verifier.

Checks only what a Controller/browser could observe: wire structure, bounds,
sanitization and absence of internal details. Never trusts the Agent's own
claims about its behavior.

Usage:
  check_trace_response.py BODY.json --family ipv4 --target 1.1.1.1 \
      [--max-raw 1048576] [--expect-status completed] [--max-bytes 8388608]

The bearer token, when exported as TRACE_TOKEN, must not appear anywhere in the
response. Prints "PASS <check> <detail>" / "FAIL <check> <detail>" lines and
exits 1 if any check failed.
"""
import argparse
import json
import math
import os
import re
import sys

FORBIDDEN_SUBSTRINGS = [
    "/usr/local/bin/nexttrace",
    "/etc/tracecat",
    "TRACECAT_AGENT_TOKEN",
    "Permission denied",
    "operation not permitted",
    "listen ip4:icmp",
    "HOME=",
    "PATH=",
    "LC_ALL=",
    "NO_COLOR=",
    "stderr",
    "goroutine",
]

CTRL_RE = re.compile(r"[\x00-\x1f\x7f\u0080-\u009f]")  # C0/C1 controls
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
HTML_RE = re.compile(r"(?i)<\s*script|javascript\s*:|onerror\s*=|<\s*iframe")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")

results = []
failed = 0


def check(name, ok, detail=""):
    global failed
    if ok:
        results.append(("PASS", name, detail))
    else:
        failed += 1
        results.append(("FAIL", name, detail))


def walk_strings(node, path="root"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_strings(v, f"{path}[{i}]")


def is_canonical_ip(value):
    try:
        from ipaddress import ip_address

        addr = ip_address(value)
        return str(addr) == value
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("body")
    ap.add_argument("--family", required=True, choices=["ipv4", "ipv6"])
    ap.add_argument("--target", required=True)
    ap.add_argument("--token")
    ap.add_argument("--max-raw", type=int, default=1 << 20)
    ap.add_argument("--max-bytes", type=int, default=8 << 20)
    ap.add_argument("--expect-status", default="completed")
    ap.add_argument("--expect-ptr", default="", help="require a hop PTR containing this substring")
    ap.add_argument("--expect-protocol", default="icmp", choices=["icmp", "tcp", "udp"])
    ap.add_argument("--expect-port", default="", help="expected destination port for tcp/udp")
    ap.add_argument("--expect-interface", default="", help="expected echoed source interface")
    args = ap.parse_args()
    if not args.token:
        # Avoid putting the bearer token on the command line / in ps output.
        args.token = os.environ.get("TRACE_TOKEN", "")

    raw = open(args.body, "rb").read()
    check("response_size_bounded", 0 < len(raw) <= args.max_bytes, f"{len(raw)} bytes")
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        check("valid_utf8", False, "response is not valid UTF-8")
        report()
        return 1
    check("valid_utf8", True, "")

    if args.token:
        check("no_token_in_response", args.token not in body, "")

    for bad in FORBIDDEN_SUBSTRINGS:
        check(f"no_{re.sub(r'[^a-z0-9]+', '_', bad.lower()).strip('_')}", bad not in body, repr(bad))

    try:
        doc = json.loads(body)
    except json.JSONDecodeError as exc:
        check("json_parses", False, str(exc))
        report()
        return 1
    check("json_parses", True, "")

    schema = doc.get("schema_version")
    check("schema_version", schema == "tracecat.agent.v1", repr(schema))

    status = doc.get("status")
    check(
        "status_terminal",
        status in ("completed", "failed", "timed_out", "cancelled"),
        repr(status),
    )
    check("status_expected", status == args.expect_status, f"want={args.expect_status} got={status!r}")

    check("family_echo", doc.get("family") == args.family, repr(doc.get("family")))
    check("protocol_echo", doc.get("protocol") == args.expect_protocol, f"want={args.expect_protocol} got={doc.get('protocol')!r}")
    if args.expect_protocol in ("tcp", "udp"):
        check("port_echo", doc.get("port") == int(args.expect_port), f"want={args.expect_port} got={doc.get('port')!r}")
    else:
        check("icmp_omits_port", "port" not in doc, f"port={doc.get('port')!r}")
    if args.expect_interface:
        check("interface_echo", doc.get("interface") == args.expect_interface, f"want={args.expect_interface} got={doc.get('interface')!r}")
    else:
        check("auto_omits_interface", "interface" not in doc, f"interface={doc.get('interface')!r}")
    check("target_echo", doc.get("target_ip") == args.target, repr(doc.get("target_ip")))
    check("target_canonical", is_canonical_ip(doc.get("target_ip") or ""), repr(doc.get("target_ip")))
    job = doc.get("job_id") or ""
    check("job_id_shape", bool(re.fullmatch(r"[A-Za-z0-9_-]{8,128}", job)), repr(job)[:64])
    node = doc.get("node_id") or ""
    check("node_id_present", bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", node)), repr(node))

    for field in ("started_at", "ended_at"):
        value = doc.get(field) or ""
        check(f"{field}_shape", bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z", value)), repr(value))
    duration = doc.get("duration_ms")
    check(
        "duration_bounded",
        isinstance(duration, int) and 0 <= duration <= 180_000,
        repr(duration),
    )

    hops = doc.get("hops") or []
    check("hops_is_list", isinstance(hops, list), type(hops).__name__)
    if status == "completed":
        check("hops_present", len(hops) > 0, f"{len(hops)} hops")

    summary = doc.get("summary") or {}
    check("summary_hop_count", summary.get("hop_count") == len(hops), f"{summary.get('hop_count')} vs {len(hops)}")
    probes = 0
    replies = 0
    prev_ttl = 0
    ttl_monotonic = True
    structure_ok = True
    for hop in hops:
        ttl = hop.get("ttl")
        if not isinstance(ttl, int) or ttl < 1 or ttl < prev_ttl:
            ttl_monotonic = False
            structure_ok = False
        prev_ttl = ttl if isinstance(ttl, int) else prev_ttl
        hop_probes = hop.get("probes")
        if not isinstance(hop_probes, list) or not hop_probes:
            structure_ok = False
            continue
        for probe in hop_probes:
            probes += 1
            if not isinstance(probe.get("success"), bool):
                structure_ok = False
            if probe.get("success"):
                replies += 1
                addr = probe.get("address")
                if not addr or not is_canonical_ip(addr):
                    check("probe_address_canonical", False, f"ttl={ttl} address={addr!r}")
                rtt = probe.get("rtt_ms")
                if rtt is not None and not (
                    isinstance(rtt, (int, float))
                    and not isinstance(rtt, bool)
                    and 0 < rtt < 120_000
                    and not math.isnan(rtt)
                ):
                    check("probe_rtt_sane", False, f"ttl={ttl} rtt={rtt!r}")
                if probe.get("error_code"):
                    check("probe_success_has_no_error", False, f"ttl={ttl} {probe.get('error_code')!r}")
            else:
                if probe.get("address"):
                    check("probe_failure_has_no_address", False, f"ttl={ttl} {probe.get('address')!r}")
                if probe.get("rtt_ms") not in (None,):
                    check("probe_failure_has_no_rtt", False, f"ttl={ttl} {probe.get('rtt_ms')!r}")
                if probe.get("error_code") not in ("no_reply", "unreachable", "unknown"):
                    check(
                        "probe_failure_error_code",
                        False,
                        f"ttl={ttl} {probe.get('error_code')!r}",
                    )
            asn = probe.get("asn")
            if asn is not None and not (isinstance(asn, int) and 0 < asn <= 0xFFFFFFFF):
                check("probe_asn_range", False, f"ttl={ttl} asn={asn!r}")
            lat, lng = probe.get("lat"), probe.get("lng")
            if lat is not None and not (isinstance(lat, (int, float)) and -90 <= lat <= 90):
                check("probe_lat_range", False, f"ttl={ttl} lat={lat!r}")
            if lng is not None and not (isinstance(lng, (int, float)) and -180 <= lng <= 180):
                check("probe_lng_range", False, f"ttl={ttl} lng={lng!r}")
            mpls = probe.get("mpls")
            if mpls is not None and (not isinstance(mpls, list) or len(mpls) > 8):
                check("probe_mpls_bounded", False, f"ttl={ttl} mpls={mpls!r}")
    check("hop_ttl_monotonic", ttl_monotonic, "")
    check("hop_structure", structure_ok, "")
    check("summary_probes", summary.get("probes") == probes, f"{summary.get('probes')} vs {probes}")
    check("summary_replies", summary.get("replies") == replies, f"{summary.get('replies')} vs {replies}")
    reached = summary.get("reached_destination")
    check("summary_reached_bool", isinstance(reached, bool), repr(reached))

    if args.expect_ptr:
        ptrs = [p.get("ptr") for h in hops for p in h.get("probes", []) if p.get("ptr")]
        check(
            "expected_ptr_present",
            any(args.expect_ptr.lower() in (ptr or "").lower() for ptr in ptrs),
            f"want~{args.expect_ptr} got={ptrs[:4]}",
        )

    raw_result = doc.get("raw_result")
    truncated = doc.get("raw_result_truncated", False)
    check("raw_truncated_bool", isinstance(truncated, bool), repr(truncated))
    if raw_result is not None:
        encoded = json.dumps(raw_result).encode()
        check("raw_result_bounded", len(encoded) <= args.max_raw, f"{len(encoded)} bytes <= {args.max_raw}")
        check("raw_result_object", isinstance(raw_result, dict), type(raw_result).__name__)
        check("raw_result_not_truncated", truncated is False, f"truncated={truncated}")
    else:
        check("raw_result_present_when_parseable", status != "completed", f"status={status}")

    # Every string that reaches a browser is plain data: no controls, ANSI or HTML.
    bad_ctrl, bad_ansi, bad_html = [], [], []
    for path, value in walk_strings(doc):
        if CTRL_RE.search(value):
            bad_ctrl.append(path)
        if ANSI_RE.search(value):
            bad_ansi.append(path)
        if HTML_RE.search(value):
            bad_html.append(path)
    check("no_control_chars", not bad_ctrl, ",".join(bad_ctrl[:5]))
    check("no_ansi_escapes", not bad_ansi, ",".join(bad_ansi[:5]))
    check("no_html_markup", not bad_html, ",".join(bad_html[:5]))

    # Error envelopes (if present) must be a stable code and a safe message.
    err = doc.get("error")
    if err is not None:
        check(
            "error_code_stable",
            err.get("code")
            in (
                "nexttrace_unavailable",
                "nexttrace_failed",
                "parse_error",
                "timeout",
                "cancelled",
                "output_too_large",
                "internal",
            ),
            repr(err.get("code")),
        )
        check("error_message_safe", not any(b in (err.get("message") or "") for b in FORBIDDEN_SUBSTRINGS), "")

    return report()


def report():
    for status, name, detail in results:
        print(f"{status} {name} {detail}".rstrip())
    print(f"SUMMARY {len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
