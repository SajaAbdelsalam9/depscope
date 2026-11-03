from depscope.comparator import compare
from depscope.html_report import esc, render_compare_html, render_scan_html, write_html
from depscope.models import Dependency, Finding
from depscope.report import build_compare_report, build_report

REQ = Dependency("requests", "2.19.0")
FLASK = Dependency("flask", "2.0.1")
JINJA = Dependency("jinja2", "2.10")
EVIL = '<script>alert("x")</script>'


def make(dep, key, severity=None, fixed=(), summary="plain summary"):
    return Finding(
        dependency=dep, key=key, ids=(key,), summary=summary,
        advisory_severity=severity, fixed_versions=tuple(fixed),
    )


def scan_page(findings=(), errors=()):
    report = build_report("req.txt", [REQ, FLASK], [], list(findings), list(errors), "2026-01-01")
    return render_scan_html(report)


def compare_page(errors=()):
    result = compare(
        [REQ], [make(REQ, "OLD", "HIGH", ["2.20.0"])],
        [Dependency("requests", "2.34.2"), JINJA], [make(JINJA, "NEW", "HIGH", ["2.10.1"])],
    )
    report = build_compare_report("b.txt", "a.txt", [], [], [], [], result, list(errors), "2026-01-01")
    return render_compare_html(report)


def test_esc_handles_none_and_markup():
    assert esc(None) == ""
    assert esc("<b>&") == "&lt;b&gt;&amp;"


def test_untrusted_summary_is_escaped_in_scan_report():
    page = scan_page([make(REQ, "A", "HIGH", summary=EVIL)])
    assert EVIL not in page
    assert "&lt;script&gt;" in page


def test_untrusted_text_is_escaped_in_compare_report():
    result = compare([], [], [JINJA], [make(JINJA, "NEW", summary=EVIL)])
    report = build_compare_report("b", "a", [], [], [], [], result, [], "2026-01-01")
    page = render_compare_html(report)
    assert EVIL not in page


def test_page_blocks_scripts_and_external_resources():
    page = scan_page([make(REQ, "A", "HIGH")])
    assert "default-src 'none'" in page
    for forbidden in ("<script", "src=", "href=", "<link"):
        assert forbidden not in page.lower()


def test_scan_page_states_limitations_and_method():
    page = scan_page()
    assert "not CVSS" in page
    assert "Limitations of this analysis" in page
    assert "not proof that it is safe" in page


def test_failed_lookup_is_visible_in_scan_page():
    page = scan_page(errors=[(FLASK, "simulated outage")])
    assert "lookup failed" in page
    assert "NOT CHECKED" in page
    assert "simulated outage" in page


def test_compare_page_has_all_sections_and_findings():
    page = compare_page()
    for heading in ("Newly introduced vulnerabilities", "Resolved vulnerabilities",
                    "Persistent vulnerabilities", "Dependency changes"):
        assert heading in page
    assert "NEW" in page and "OLD" in page
    assert "dependency is new" in page


def test_compare_page_warns_about_packages_not_compared():
    page = compare_page(errors=[(REQ, "boom")])
    assert "could not be checked" in page
    assert "NOT COMPARED" in page


def test_write_html_creates_folder_and_file(tmp_path):
    path = tmp_path / "out" / "page.html"
    write_html("<p>hi</p>", path)
    assert path.read_text(encoding="utf-8") == "<p>hi</p>"
