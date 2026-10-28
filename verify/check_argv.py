#!/usr/bin/env python3
"""Assert the exact NextTrace argv shape TraceCat builds (independent verifier).

The Agent must never let a request influence flags, order or the executable;
this checker validates the observed `/proc/<pid>/cmdline` of a live child.

Usage:
  check_argv.py "/usr/local/bin/nexttrace -4 -T --json -q 1 -m 8 --timeout 1000 -p 443 1.1.1.1" \\
      --protocol tcp --port 443 --interface eth0 --target 1.1.1.1 --family ipv4

Exit code 0 when the vector has exactly the documented shape.
"""
import argparse
import sys

results = []
failed = 0


def check(name, ok, detail=""):
    global failed
    results.append((ok, name, detail))
    if not ok:
        failed += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmdline")
    ap.add_argument("--binary", default="/usr/local/bin/nexttrace")
    ap.add_argument("--protocol", choices=["icmp", "tcp", "udp"], required=True)
    ap.add_argument("--port", default="")
    ap.add_argument("--interface", default="")
    ap.add_argument("--target", required=True)
    ap.add_argument("--family", choices=["ipv4", "ipv6"], required=True)
    args = ap.parse_args()

    argv = args.cmdline.split()
    check("binary_is_fixed_path", bool(argv) and argv[0] == args.binary, argv[0] if argv else "empty")
    if not argv:
        return report()

    family = {"ipv4": ("-4", "--ipv4"), "ipv6": ("-6", "--ipv6")}[args.family]
    check("family_flag_first", len(argv) > 1 and argv[1] in family, argv[1] if len(argv) > 1 else "missing")
    idx = 2

    expected_protocol = {"icmp": None, "tcp": ("-T", "--tcp"), "udp": ("-U", "--udp")}[args.protocol]
    if expected_protocol:
        check(
            "protocol_flag_second",
            idx < len(argv) and argv[idx] in expected_protocol,
            argv[idx] if idx < len(argv) else "missing",
        )
        idx += 1
    else:
        check("icmp_has_no_protocol_flag", not any(a in ("-T", "--tcp", "-U", "--udp") for a in argv), "")

    if args.interface:
        check(
            "device_pair_after_protocol",
            idx + 1 < len(argv) and argv[idx] in ("-D", "--dev") and argv[idx + 1] == args.interface,
            f"{argv[idx:idx + 2]}" if idx < len(argv) else "missing",
        )
        idx += 2
    else:
        check("auto_has_no_device_flag", not any(a in ("-D", "--dev") for a in argv), "")

    check("json_flag", idx < len(argv) and argv[idx] == "--json", argv[idx] if idx < len(argv) else "missing")
    idx += 1
    check("queries_pair", idx + 1 < len(argv) and argv[idx] in ("-q", "--queries") and argv[idx + 1].isdigit(), "")
    idx += 2
    check("max_hops_pair", idx + 1 < len(argv) and argv[idx] in ("-m", "--max-hops") and argv[idx + 1].isdigit(), "")
    idx += 2
    check(
        "timeout_pair",
        idx + 1 < len(argv) and argv[idx] == "--timeout" and argv[idx + 1].isdigit(),
        "",
    )
    idx += 2

    if args.protocol in ("tcp", "udp"):
        check(
            "port_pair_immediately_before_target",
            idx + 2 < len(argv) and argv[idx] in ("-p", "--port") and argv[idx + 1] == str(args.port),
            f"{argv[idx:idx + 2]}" if idx < len(argv) else "missing",
        )
        idx += 2
    else:
        check("icmp_has_no_port_flag", not any(a in ("-p", "--port") for a in argv), "")

    check("target_is_final_argument", idx < len(argv) and argv[idx] == args.target, argv[idx] if idx < len(argv) else "missing")
    check("no_trailing_arguments", idx + 1 == len(argv), f"{argv[idx + 1:]}")
    for flag in ("-T", "--tcp", "-U", "--udp", "-p", "--port", "-D", "--dev", "--json"):
        check(f"single_occurrence_{flag}", argv.count(flag) <= 1, str(argv.count(flag)))
    return report()


def report():
    for ok, name, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {name} {detail}".rstrip())
    print(f"SUMMARY {len(results) - failed}/{len(results)} argv checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
