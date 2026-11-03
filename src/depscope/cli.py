import argparse
import sys

from depscope.comparator import compare, package_key
from depscope.parser import parse_file
from depscope.remediation import print_recommendations
from depscope.scanner import scan


def describe(finding):
    label = finding.advisory_severity or "severity not available"
    fix = ", ".join(finding.fixed_versions) if finding.fixed_versions else "no fixed version listed"
    dep = finding.dependency
    return f"{finding.key} [{label}] in {dep.name}=={dep.version}, fix: {fix}\n      {finding.summary}"


def run_scan(path):
    dependencies, issues = parse_file(path)
    findings, errors = scan(dependencies)

    print(f"Dependencies analyzed: {len(dependencies)}")
    print(f"Distinct vulnerabilities: {len(findings)}")

    for dependency in dependencies:
        own = [f for f in findings if f.dependency == dependency]
        print(f"\n{dependency.name}=={dependency.version}: {len(own)} finding(s)")
        for f in own:
            label = f.advisory_severity or "severity not available"
            fix = ", ".join(f.fixed_versions) if f.fixed_versions else "no fixed version listed"
            print(f"  - {f.key} [{label}] fix: {fix}")
            print(f"    {f.summary}")

    print_recommendations(dependencies, findings)
    if issues:
        print("\nUnsupported lines (NOT analyzed):")
        for issue in issues:
            print(f"  line {issue.line_number}: {issue.text}")

    if errors:
        print("\nCould not be checked (lookup failed, result unknown):")
        for dependency, message in errors:
            print(f"  {dependency.name}=={dependency.version}: {message}")

    return 1 if errors else 0


def run_compare(before_path, after_path):
    before_deps, before_issues = parse_file(before_path)
    after_deps, after_issues = parse_file(after_path)
    before_findings, before_errors = scan(before_deps)
    after_findings, after_errors = scan(after_deps)

    # A package that could not be checked in EITHER snapshot is left out entirely,
    # so a failed lookup is never mistaken for "no vulnerabilities".
    unchecked = {package_key(d) for d, _ in before_errors + after_errors}

    def checked(dependency):
        return package_key(dependency) not in unchecked

    result = compare(
        [d for d in before_deps if checked(d)],
        [f for f in before_findings if checked(f.dependency)],
        [d for d in after_deps if checked(d)],
        [f for f in after_findings if checked(f.dependency)],
    )

    print("DEPENDENCY CHANGES")
    print(f"  Added:     {[f'{d.name}=={d.version}' for d in result.added]}")
    print(f"  Removed:   {[f'{d.name}=={d.version}' for d in result.removed]}")
    print(f"  Updated:   {[f'{u.name} {u.before} -> {u.after}' for u in result.updated]}")
    print(f"  Unchanged: {[f'{d.name}=={d.version}' for d in result.unchanged]}")

    print(f"\nNEWLY INTRODUCED VULNERABILITIES ({len(result.new_findings)})")
    for change in result.new_findings:
        print(f"  - {describe(change.finding)}\n      why: {change.reason}")

    print(f"\nRESOLVED VULNERABILITIES ({len(result.resolved_findings)})")
    for change in result.resolved_findings:
        print(f"  - {describe(change.finding)}\n      why: {change.reason}")

    print(f"\nPERSISTENT VULNERABILITIES ({len(result.persistent_findings)})")
    for finding in result.persistent_findings:
        print(f"  - {describe(finding)}")

    print(
        f"\nTotals for reference only (before: {len(before_findings)}, "
        f"after: {len(after_findings)}). The lists above are what changed."
    )

    unsupported = [("before", i) for i in before_issues] + [("after", i) for i in after_issues]
    if unsupported:
        print("\nUnsupported lines (NOT analyzed):")
        for where, issue in unsupported:
            print(f"  {where} line {issue.line_number}: {issue.text}")

    all_errors = before_errors + after_errors
    if all_errors:
        print("\nNOT COMPARED (lookup failed, result unknown):")
        for dependency, message in all_errors:
            print(f"  {dependency.name}=={dependency.version}: {message}")

    return 1 if all_errors else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="DepScope: dependency vulnerability analysis")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_cmd = commands.add_parser("scan", help="scan one requirements file")
    scan_cmd.add_argument("requirements")

    compare_cmd = commands.add_parser("compare", help="compare two requirements files")
    compare_cmd.add_argument("before")
    compare_cmd.add_argument("after")

    args = parser.parse_args()
    if args.command == "scan":
        return run_scan(args.requirements)
    return run_compare(args.before, args.after)


if __name__ == "__main__":
    sys.exit(main())
