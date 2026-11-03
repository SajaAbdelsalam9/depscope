import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from depscope.prioritizer import prioritize
from depscope.remediation import recommend

TOOL_VERSION = "0.1.0"

PRIORITY_METHOD = (
    "DepScope priority (P1-P4) is a transparent heuristic: advisory severity label "
    "+ whether a fix is listed (+ whether the finding is new, in compare mode). "
    "It is not CVSS and not an industry standard."
)

LIMITATIONS = (
    "Results come from the OSV database only. A package with no findings has no KNOWN "
    "vulnerabilities in OSV, which is not proof that it is safe.",
    "Only exact == pins are analyzed. Other lines are listed as unsupported and are not checked.",
    "Transitive dependencies are analyzed only if they appear in the file (for example from pip freeze).",
    "Severity labels come from the advisory source. DepScope does not calculate CVSS scores.",
    "Priority levels are DepScope's own heuristic and ignore whether the vulnerable code is used or exposed.",
    "Suggested versions come from advisory fix data and are not tested against your application.",
    "Only the first page of OSV results is read, so very large result sets may be incomplete.",
)


def build_report(source, dependencies, issues, findings, errors, generated_at=None):
    failed = {dependency for dependency, _ in errors}

    ranked = [prioritize(f) for f in findings]
    ranked.sort(key=lambda p: (-p.score, p.finding.dependency.name, p.finding.key))

    distribution = {}
    for f in findings:
        label = f.advisory_severity.upper() if f.advisory_severity else "not available"
        distribution[label] = distribution.get(label, 0) + 1

    inventory = []
    for d in dependencies:
        is_failed = d in failed
        inventory.append(
            {
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "status": "lookup failed" if is_failed else "analyzed",
                "findings": None if is_failed else sum(1 for f in findings if f.dependency == d),
            }
        )

    recommendations = []
    for d in dependencies:
        if not any(f.dependency == d for f in findings):
            continue
        rec = recommend(d, findings)
        recommendations.append(
            {
                "package": d.name,
                "installed_version": d.version,
                "suggested_version": rec.target_version,
                "no_fix_listed_for": list(rec.unfixed_keys),
            }
        )

    return {
        "tool": {"name": "DepScope", "version": TOOL_VERSION},
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_file": source,
        "summary": {
            "dependencies_listed": len(dependencies),
            "dependencies_analyzed": len(dependencies) - len(failed),
            "dependencies_lookup_failed": len(failed),
            "unsupported_lines": len(issues),
            "distinct_vulnerabilities": len(findings),
            "severity_distribution_advisory_labels": distribution,
        },
        "dependencies": inventory,
        "findings": [
            {
                "key": p.finding.key,
                "all_ids": list(p.finding.ids),
                "package": p.finding.dependency.name,
                "installed_version": p.finding.dependency.version,
                "summary": p.finding.summary,
                "advisory_severity": p.finding.advisory_severity,
                "cvss_vectors": list(p.finding.cvss_vectors),
                "fixed_versions": list(p.finding.fixed_versions),
                "priority_level": p.level,
                "priority_score": p.score,
                "priority_reasons": list(p.reasons),
            }
            for p in ranked
        ],
        "recommendations": recommendations,
        "unsupported_lines": [
            {"line": i.line_number, "text": i.text, "reason": i.reason} for i in issues
        ],
        "lookup_errors": [
            {"package": f"{d.name}=={d.version}", "error": message} for d, message in errors
        ],
        "priority_method": PRIORITY_METHOD,
        "limitations": list(LIMITATIONS),
    }


def write_json(report, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)


CSV_COLUMNS = (
    "package", "installed_version", "finding_key", "all_ids", "advisory_severity",
    "priority_level", "priority_score", "fixed_versions", "summary",
)


def _safe_cell(value):
    """Stop spreadsheet apps from running text as a formula (CSV injection)."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def write_csv(report, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for f in report["findings"]:
            writer.writerow(
                {
                    "package": _safe_cell(f["package"]),
                    "installed_version": _safe_cell(f["installed_version"]),
                    "finding_key": _safe_cell(f["key"]),
                    "all_ids": _safe_cell("; ".join(f["all_ids"])),
                    "advisory_severity": _safe_cell(f["advisory_severity"] or "not available"),
                    "priority_level": _safe_cell(f["priority_level"]),
                    "priority_score": _safe_cell(f["priority_score"]),
                    "fixed_versions": _safe_cell("; ".join(f["fixed_versions"])),
                    "summary": _safe_cell(f["summary"]),
                }
            )


def write_reports(source, dependencies, issues, findings, errors, json_path=None, csv_path=None):
    if not (json_path or csv_path):
        return
    report = build_report(source, dependencies, issues, findings, errors)
    if json_path:
        write_json(report, json_path)
        print(f"\nJSON report written to {json_path}")
    if csv_path:
        write_csv(report, csv_path)
        print(f"CSV report written to {csv_path} (findings only)")


COMPARE_LIMITATIONS = LIMITATIONS + (
    "Packages whose OSV lookup failed in either snapshot are excluded from the comparison "
    "and listed under not_compared. Their changes are unknown.",
    "A finding that is new on an unchanged version may have been disclosed between the two "
    "scans, or the earlier data may have been incomplete. DepScope cannot tell which.",
)


def _basic_finding(finding):
    return {
        "key": finding.key,
        "all_ids": list(finding.ids),
        "package": finding.dependency.name,
        "installed_version": finding.dependency.version,
        "summary": finding.summary,
        "advisory_severity": finding.advisory_severity,
        "cvss_vectors": list(finding.cvss_vectors),
        "fixed_versions": list(finding.fixed_versions),
    }


def _ranked_entry(finding, is_new):
    p = prioritize(finding, is_new=is_new)
    entry = _basic_finding(finding)
    entry["priority_level"] = p.level
    entry["priority_score"] = p.score
    entry["priority_reasons"] = list(p.reasons)
    return entry


def build_compare_report(
    before_path, after_path, before_deps, after_deps,
    before_issues, after_issues, result, errors, generated_at=None,
):
    new_ranked = [prioritize(c.finding, is_new=True) for c in result.new_findings]
    reasons = {c.finding: c.reason for c in result.new_findings}
    new_ranked.sort(key=lambda p: (-p.score, p.finding.dependency.name, p.finding.key))

    new_entries = []
    for p in new_ranked:
        entry = _ranked_entry(p.finding, is_new=True)
        entry["reason"] = reasons[p.finding]
        new_entries.append(entry)

    resolved_entries = []
    for change in result.resolved_findings:
        entry = _basic_finding(change.finding)
        entry["reason"] = change.reason
        resolved_entries.append(entry)

    persistent = sorted(
        result.persistent_findings,
        key=lambda f: (-prioritize(f).score, f.dependency.name, f.key),
    )

    return {
        "tool": {"name": "DepScope", "version": TOOL_VERSION},
        "report_type": "comparison",
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "before_file": before_path,
        "after_file": after_path,
        "summary": {
            "dependencies_added": len(result.added),
            "dependencies_removed": len(result.removed),
            "dependencies_updated": len(result.updated),
            "dependencies_unchanged": len(result.unchanged),
            "new_vulnerabilities": len(result.new_findings),
            "resolved_vulnerabilities": len(result.resolved_findings),
            "persistent_vulnerabilities": len(result.persistent_findings),
            "packages_not_compared": len(errors),
        },
        "dependency_changes": {
            "added": [{"name": d.name, "version": d.version} for d in result.added],
            "removed": [{"name": d.name, "version": d.version} for d in result.removed],
            "updated": [
                {"name": u.name, "before": u.before, "after": u.after} for u in result.updated
            ],
            "unchanged": [{"name": d.name, "version": d.version} for d in result.unchanged],
        },
        "new_vulnerabilities": new_entries,
        "resolved_vulnerabilities": resolved_entries,
        "persistent_vulnerabilities": [_ranked_entry(f, is_new=False) for f in persistent],
        "not_compared": [
            {"package": f"{d.name}=={d.version}", "error": message} for d, message in errors
        ],
        "unsupported_lines": [
            {"snapshot": snapshot, "line": i.line_number, "text": i.text, "reason": i.reason}
            for snapshot, issues in (("before", before_issues), ("after", after_issues))
            for i in issues
        ],
        "priority_method": PRIORITY_METHOD,
        "limitations": list(COMPARE_LIMITATIONS),
    }


def write_compare_json(
    before_path, after_path, before_deps, after_deps,
    before_issues, after_issues, result, errors, json_path=None,
):
    if not json_path:
        return
    report = build_compare_report(
        before_path, after_path, before_deps, after_deps,
        before_issues, after_issues, result, errors,
    )
    write_json(report, json_path)
    print(f"\nJSON comparison report written to {json_path}")
