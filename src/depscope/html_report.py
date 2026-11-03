import html
from pathlib import Path

CSS = """
body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #1a1a1a; }
h1 { margin-bottom: 0.2rem; }
h2 { margin-top: 2rem; border-bottom: 2px solid #ddd; padding-bottom: 0.3rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; margin: 0.5rem 0; }
th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
.meta { color: #555; }
.warn { background: #fff4d6; border: 1px solid #e0b84c; padding: 0.6rem 0.8rem; }
"""


def esc(value):
    """Escape any value so it is shown as text and never interpreted as HTML."""
    return html.escape("" if value is None else str(value), quote=True)


def _table(headers, rows):
    if not rows:
        return "<p><em>None.</em></p>"
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section(title, content):
    return f"<h2>{esc(title)}</h2>{content}"


def _page(title, body):
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{esc(title)}</title><style>{CSS}</style></head><body>{body}</body></html>"
    )


def _header(title, meta_lines):
    meta = "".join(f"<div>{esc(line)}</div>" for line in meta_lines)
    return f"<h1>{esc(title)}</h1><div class=\"meta\">{meta}</div>"


def _footer(report):
    items = "".join(f"<li>{esc(text)}</li>" for text in report["limitations"])
    return _section(
        "How priorities are calculated", f"<p>{esc(report['priority_method'])}</p>"
    ) + _section("Limitations of this analysis", f"<ul>{items}</ul>")


def _label(key):
    return key.replace("_", " ").capitalize()


def write_html(text, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")


def render_scan_html(report):
    summary = report["summary"]
    distribution = summary["severity_distribution_advisory_labels"]

    summary_rows = [[_label(k), v] for k, v in summary.items() if not isinstance(v, dict)]
    distribution_rows = [[label, count] for label, count in distribution.items()]

    inventory_rows = [
        [d["name"], d["version"], d["ecosystem"], d["status"],
         "n/a" if d["findings"] is None else d["findings"]]
        for d in report["dependencies"]
    ]
    finding_rows = [
        [f"{f['priority_level']} (score {f['priority_score']})", f["key"],
         f"{f['package']} {f['installed_version']}", f["advisory_severity"] or "not available",
         "; ".join(f["fixed_versions"]) or "none listed", f["summary"]]
        for f in report["findings"]
    ]
    recommendation_rows = [
        [r["package"], r["installed_version"], r["suggested_version"] or "none listed",
         "; ".join(r["no_fix_listed_for"])]
        for r in report["recommendations"]
    ]

    body = _header(
        "DepScope Security Assessment",
        [f"Source file: {report['source_file']}", f"Generated: {report['generated_at']}",
         f"Tool: {report['tool']['name']} {report['tool']['version']}"],
    )
    body += _section("Summary", _table(["Item", "Value"], summary_rows))
    body += _section(
        "Advisory severity labels (from the advisory source, not CVSS)",
        _table(["Label", "Findings"], distribution_rows),
    )
    body += _section(
        "Dependency inventory",
        _table(["Package", "Version", "Ecosystem", "Status", "Findings"], inventory_rows),
    )
    body += _section(
        "Vulnerability findings (highest priority first)",
        _table(["DepScope priority", "Vulnerability", "Package", "Advisory severity",
                "Fixed in", "Summary"], finding_rows),
    )
    body += _section(
        "Suggested upgrades",
        _table(["Package", "Installed", "Suggested version", "No fix listed for"],
               recommendation_rows),
    )
    if report["lookup_errors"]:
        body += _section(
            "NOT CHECKED: lookup failed, result unknown",
            _table(["Package", "Error"], [[e["package"], e["error"]] for e in report["lookup_errors"]]),
        )
    if report["unsupported_lines"]:
        body += _section(
            "Unsupported lines (not analyzed)",
            _table(["Line", "Text", "Reason"],
                   [[u["line"], u["text"], u["reason"]] for u in report["unsupported_lines"]]),
        )
    body += _footer(report)
    return _page("DepScope Security Assessment", body)


def render_compare_html(report):
    summary = report["summary"]
    changes = report["dependency_changes"]

    change_rows = (
        [["Added", d["name"], "", d["version"]] for d in changes["added"]]
        + [["Removed", d["name"], d["version"], ""] for d in changes["removed"]]
        + [["Updated", u["name"], u["before"], u["after"]] for u in changes["updated"]]
        + [["Unchanged", d["name"], d["version"], d["version"]] for d in changes["unchanged"]]
    )
    new_rows = [
        [f"{f['priority_level']} (score {f['priority_score']})", f["key"],
         f"{f['package']} {f['installed_version']}", f["advisory_severity"] or "not available",
         "; ".join(f["fixed_versions"]) or "none listed", f["reason"], f["summary"]]
        for f in report["new_vulnerabilities"]
    ]
    resolved_rows = [
        [f["key"], f"{f['package']} {f['installed_version']}",
         f["advisory_severity"] or "not available", f["reason"], f["summary"]]
        for f in report["resolved_vulnerabilities"]
    ]
    persistent_rows = [
        [f"{f['priority_level']} (score {f['priority_score']})", f["key"],
         f"{f['package']} {f['installed_version']}", f["advisory_severity"] or "not available",
         "; ".join(f["fixed_versions"]) or "none listed", f["summary"]]
        for f in report["persistent_vulnerabilities"]
    ]

    body = _header(
        "DepScope Change-Aware Comparison",
        [f"Before: {report['before_file']}", f"After: {report['after_file']}",
         f"Generated: {report['generated_at']}",
         f"Tool: {report['tool']['name']} {report['tool']['version']}"],
    )
    body += _section("Summary", _table(["Item", "Value"], [[_label(k), v] for k, v in summary.items()]))
    body += _section("Dependency changes", _table(["Change", "Package", "Before", "After"], change_rows))
    body += _section(
        "Newly introduced vulnerabilities",
        _table(["DepScope priority", "Vulnerability", "Package", "Advisory severity",
                "Fixed in", "Why it is new", "Summary"], new_rows),
    )
    body += _section(
        "Resolved vulnerabilities",
        _table(["Vulnerability", "Package (earlier version)", "Advisory severity",
                "Why resolved", "Summary"], resolved_rows),
    )
    body += _section(
        "Persistent vulnerabilities (present in both snapshots)",
        _table(["DepScope priority", "Vulnerability", "Package", "Advisory severity",
                "Fixed in", "Summary"], persistent_rows),
    )
    if report["not_compared"]:
        body += (
            '<div class="warn">Some packages could not be checked and are excluded from the '
            "comparison. Their changes are unknown.</div>"
        )
        body += _section(
            "NOT COMPARED: lookup failed",
            _table(["Package", "Error"], [[e["package"], e["error"]] for e in report["not_compared"]]),
        )
    if report["unsupported_lines"]:
        body += _section(
            "Unsupported lines (not analyzed)",
            _table(["Snapshot", "Line", "Text", "Reason"],
                   [[u["snapshot"], u["line"], u["text"], u["reason"]] for u in report["unsupported_lines"]]),
        )
    body += _footer(report)
    return _page("DepScope Change-Aware Comparison", body)
