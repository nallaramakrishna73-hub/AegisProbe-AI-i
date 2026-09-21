"""
PDF Report Generator for AegisProbe AI using ReportLab.
Produces a clean, multi-page security audit PDF document.
"""

import html
from pathlib import Path
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_report(scan_data: Dict[str, Any], output_path: str) -> str:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(p),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569')
    )
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    finding_title = ParagraphStyle(
        'FTitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0f172a'),
        fontName="Helvetica-Bold"
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("AegisProbe AI — Security Assessment Report", title_style))
    target = scan_data.get("target", "localhost")
    scan_id = scan_data.get("scan_id", "scan-001")
    date_str = scan_data.get("started_at", "2026-09-21")
    elements.append(Paragraph(f"Target: {target}  |  Scan ID: {scan_id}  |  Generated: {date_str}", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#cbd5e1'), spaceAfter=15))

    # Executive Summary Table
    risk = scan_data.get("risk_assessment", {})
    summary_data = [
        ["Metric", "Value"],
        ["Target Endpoint", target],
        ["Overall Risk Level", risk.get("level", "INFO")],
        ["Risk Score (0-100)", f"{risk.get('score', 0)} ({risk.get('status', 'OK')})"],
        ["Total Tests Executed", str(scan_data.get("total_tests", 0))],
        ["Tests Passed / Failed", f"{scan_data.get('passed_tests', 0)} / {scan_data.get('failed_tests', 0)}"],
        ["Total Vulnerabilities", str(len(scan_data.get("findings", [])))]
    ]
    t = Table(summary_data, colWidths=[200, 330])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15))

    # Findings Section
    elements.append(Paragraph("Identified Findings", h2_style))
    findings = scan_data.get("findings", [])
    if not findings:
        elements.append(Paragraph("No vulnerabilities detected in authorized test suites.", body_style))
    else:
        for f in findings:
            fid = html.escape(str(f.get("id", "F-001")))
            ftitle = html.escape(str(f.get("title", "")))
            fsev = html.escape(str(f.get("severity", "MEDIUM")))
            fdesc = html.escape(str(f.get("description", "")))
            fevid = html.escape(str(f.get("evidence", ""))[:180])
            fremed = html.escape(str(f.get("remediation", "")))

            f_table_data = [
                [Paragraph(f"[{fid}] {ftitle}", finding_title), Paragraph(f"Severity: {fsev}", finding_title)],
                [Paragraph(f"<b>Description:</b> {fdesc}", body_style), Paragraph(f"<b>Remediation:</b> {fremed}", body_style)],
                [Paragraph(f"<b>Evidence:</b> {fevid}", body_style), Paragraph("", body_style)]
            ]
            ftbl = Table(f_table_data, colWidths=[350, 180])
            ftbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('SPAN', (0, 2), (1, 2)),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(ftbl)
            elements.append(Spacer(1, 8))

    doc.build(elements)
    return str(p.resolve())
