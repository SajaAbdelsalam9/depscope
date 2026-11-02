import argparse
import sys

from depscope.parser import parse_file
from depscope.scanner import scan


def main() -> int:
    parser = argparse.ArgumentParser(description="DepScope: dependency vulnerability scanner")
    parser.add_argument("requirements", help="path to a requirements.txt file")
    args = parser.parse_args()

    dependencies, issues = parse_file(args.requirements)
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

    if issues:
        print("\nUnsupported lines (NOT analyzed):")
        for issue in issues:
            print(f"  line {issue.line_number}: {issue.text}")

    if errors:
        print("\nCould not be checked (lookup failed, result unknown):")
        for dependency, message in errors:
            print(f"  {dependency.name}=={dependency.version}: {message}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
