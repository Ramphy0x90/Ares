import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.scan import Scan
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.models.report import Report

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "reports"
REPORTS_DIR = settings.DATA_DIR / "reports"


def _severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def _severity_color(s: str) -> str:
    return {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }.get(s, "#6b7280")


async def _load_scan_data(db: AsyncSession, scan_id: int) -> dict:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    target = await db.get(Target, scan.target_id)
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.created_at)
    )
    vulns = result.scalars().all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = len(vulns)
    if severity_counts["critical"] > 0:
        risk_rating = "Critical"
    elif severity_counts["high"] > 0:
        risk_rating = "High"
    elif severity_counts["medium"] > 0:
        risk_rating = "Medium"
    elif severity_counts["low"] > 0:
        risk_rating = "Low"
    else:
        risk_rating = "Informational"

    sorted_vulns = sorted(vulns, key=lambda v: _severity_order(v.severity.lower()))

    scanner_names = list({v.scanner_name for v in vulns})

    duration = None
    if scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        minutes = int(delta.total_seconds() // 60)
        seconds = int(delta.total_seconds() % 60)
        duration = f"{minutes}m {seconds}s"

    return {
        "scan": scan,
        "target": target,
        "vulnerabilities": sorted_vulns,
        "severity_counts": severity_counts,
        "total_findings": total,
        "risk_rating": risk_rating,
        "scanner_names": scanner_names,
        "duration": duration,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "severity_color": _severity_color,
    }


async def generate_report(db: AsyncSession, scan_id: int, title: str, fmt: str) -> Report:
    """Generate a report for the given scan in the requested format."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    data = await _load_scan_data(db, scan_id)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_title = "".join(c if c.isalnum() or c in "-_ " else "" for c in title).strip().replace(" ", "_")
    base_name = f"{safe_title}_{timestamp}"

    if fmt == "json":
        file_path = REPORTS_DIR / f"{base_name}.json"
        _generate_json(data, file_path)
    elif fmt == "pdf":
        file_path = REPORTS_DIR / f"{base_name}.pdf"
        _generate_pdf(data, file_path)
    else:
        file_path = REPORTS_DIR / f"{base_name}.html"
        _generate_html(data, file_path)
        fmt = "html"

    report = Report(scan_id=scan_id, title=title, format=fmt, file_path=str(file_path))
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


def _generate_html(data: dict, file_path: Path) -> None:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")
    html = template.render(**data)
    file_path.write_text(html, encoding="utf-8")


def _generate_pdf(data: dict, file_path: Path) -> None:
    try:
        from weasyprint import HTML as WeasyprintHTML
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
        template = env.get_template("report.html.j2")
        html = template.render(**data)
        WeasyprintHTML(string=html).write_pdf(str(file_path))
    except ImportError:
        html_path = file_path.with_suffix(".html")
        _generate_html(data, html_path)
        file_path.write_text(
            f"PDF generation requires weasyprint. HTML report saved at: {html_path}",
            encoding="utf-8",
        )


def _generate_json(data: dict, file_path: Path) -> None:
    scan = data["scan"]
    target = data["target"]

    output = {
        "report": {
            "generated_at": data["generated_at"],
            "risk_rating": data["risk_rating"],
        },
        "target": {
            "id": target.id,
            "name": target.name,
            "host": target.host,
            "type": target.target_type,
        },
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": data["duration"],
        },
        "summary": {
            "total_findings": data["total_findings"],
            "severity_counts": data["severity_counts"],
            "scanners_used": data["scanner_names"],
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "description": v.description,
                "evidence": v.evidence,
                "remediation": v.remediation,
                "cwe_id": v.cwe_id,
                "cvss_score": v.cvss_score,
                "affected_component": v.affected_component,
                "scanner": v.scanner_name,
                "status": v.status,
            }
            for v in data["vulnerabilities"]
        ],
    }

    file_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
