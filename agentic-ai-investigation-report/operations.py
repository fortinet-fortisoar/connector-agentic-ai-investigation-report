"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .constants import LOGGER_NAME
logger = get_logger(LOGGER_NAME)

from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, ListFlowable, ListItem)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from datetime import datetime
import os
import re
from collections import Counter

def _mitre_color(count):
    if count == 0:
        return colors.whitesmoke
    if count == 1:
        return colors.lightyellow
    if count <= 3:
        return colors.orange
    return colors.red


def generate_investigation_pdf(config, params, *args, **kwargs):
    """
    FortiSOAR Operation:
    Generates Investigation PDF + MITRE Heatmap
    """

    data = params.get("investigationJSON")
    #hypo = data["questions"]
    alert_name = params.get("alertName")
    alert_id = params.get("alertid")
    kb_questions = params.get("kbQuestions")
    output_file = params.get("outputFileName")
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    story = []

    # ------------------------------------------------
    # Cover Page
    # ------------------------------------------------
    summary = data.get("summary", {})
    highlighted_summary = summary.get('highlighted_summary', "")
    sentences = re.split(r'\.\s+', highlighted_summary)
    points = [s.strip() for s in sentences if s.strip()] 
    bullet_summary = ListFlowable([ListItem(Paragraph(p, styles["BodyText"])) for p in points], bulletType='bullet')

    story.append(Paragraph("<b>Fortinet AI Investigation Report</b>", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Generated on:</b> {datetime.utcnow().strftime('%m-%d-%Y %H:%M:%S')} UTC", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Alert Name:</b> {alert_name}"))
    story.append(Paragraph(f"<b>Alert ID:</b> {alert_id}"))
    story.append(Paragraph(
        f"<b>Classification:</b> {summary.get('classification')}<br/>"
        f"<b>Confidence:</b> {summary.get('confidence')}%",
        styles["BodyText"]
    ))
    story.append(PageBreak())


    # ------------------------------------------------
    # Executive Summary
    # ------------------------------------------------
    story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    story.append(Spacer(1, 8))
    #story.append(Paragraph(summary.get("bullet_summary", ""), styles["BodyText"]))
    story.append(bullet_summary)
    story.append(PageBreak())

    # ------------------------------------------------
    # Key Findings
    # ------------------------------------------------
    styles = getSampleStyleSheet()
    # Create a custom style for table cells if you want smaller text
    table_cell_style = styles["BodyText"]
    table_cell_style.wordWrap = 'CJK'
    story.append(Paragraph("<b>Key Findings</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    table_data = [["Finding", "Importance", "Source", "Details"]]
    for f in summary.get("key_findings", []):
        wrapped_name = Paragraph(f["name"], table_cell_style)
        wrapped_details = Paragraph(f["details"], table_cell_style)
        table_data.append([[wrapped_name], f["importance"], f["source_agent"], [wrapped_details]])

    table = Table(table_data, colWidths=[150, 80, 100, 200])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0 ), (-1, -1), "TOP")]))

    story.append(table)
    story.append(PageBreak())

    # ------------------------------------------------
    # MITRE ATT&CK Heatmap
    # ------------------------------------------------
    story.append(Paragraph("<b>MITRE ATT&CK Heatmap</b>", styles["Heading2"]))
    story.append(Spacer(1, 12))

    technique_counts = Counter()

    for section in ["logs", "hypotheses"]:
        for item in data.get(section, []):
            if item.get("techniques"):
                for t in item.get("techniques", []):
                    technique_counts[t] += 1

    mitre_rows = [["Technique", "Occurrences"]]
    row_colors = []

    for technique, count in sorted(technique_counts.items()):
        mitre_rows.append([technique, str(count)])
        row_colors.append(_mitre_color(count))

    mitre_table = Table(mitre_rows, colWidths=[200, 100])

    style = [
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold")
    ]

    for i, color in enumerate(row_colors, start=1):
        style.append(("BACKGROUND", (0, i), (-1, i), color))

    mitre_table.setStyle(TableStyle(style))
    story.append(mitre_table)
    story.append(PageBreak())

    # ------------------------------------------------
    # Investigation Logs (Condensed)
    # ------------------------------------------------
    story.append(Paragraph("<b>Investigation Reasoning</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    for log in data.get("logs", []):
        story.append(Paragraph(
            f"<b>[{log['tier']}] {log['question']}</b>",
            styles["BodyText"]
        ))
        if "result" in log:
            story.append(Paragraph(
                f"Result: {log['result']}", styles["BodyText"]))
        else:
            story.append(Paragraph(
                "Result: Null", styles["BodyText"]))
        if "confidence" in log:
            story.append(Paragraph(
                f"Confidence: {log['confidence']}", styles["BodyText"]))
        else:
            story.append(Paragraph("Confidence: Null", styles["BodyText"]))
        if "evidence" in log:
            story.append(Paragraph(f"<i>{log['evidence']}</i>", styles["BodyText"]))
        else:
            story.append(Paragraph("<i>Evidence not found</i>", styles["BodyText"]))
        story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ------------------------------------------------
    # Response Playbook
    # ------------------------------------------------
    story.append(Paragraph("<b>Response Playbook</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    for section, actions in data.get("playbook", {}).items():
        story.append(Paragraph(section.replace("_", " ").title(), styles["Heading3"]))
        for act in actions:
            story.append(Paragraph(f"- {act}", styles["BodyText"]))
        story.append(Spacer(1, 8))
    story.append(PageBreak())

    # ------------------------------------------------
    # Knowledge Base Questions
    # ------------------------------------------------
    styles = getSampleStyleSheet()
    table_cell_style = styles["BodyText"]
    table_cell_style.wordWrap = 'CJK'
    story.append(Paragraph("<b>Knowledge Base Questions</b>", styles["Heading2"]))

    table_data = [["Question"]]
    end_index = len(kb_questions) - 1
    for kbq in kb_questions[1:end_index]:
        wrapped_kbq = Paragraph(kbq, table_cell_style)
        table_data.append([[wrapped_kbq]])
    
    table = Table(table_data, colWidths=[500])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.orange),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP")]))

    story.append(Spacer(1, 8))
    story.append(table)
    story.append(PageBreak())

    # ------------------------------------------------
    # All Questions Asked During Investigation
    # ------------------------------------------------

    all_questions = data.get("all_questions")
    styles = getSampleStyleSheet()
    table_cell_style = styles["BodyText"]
    table_cell_style.wordWrap = 'CJK'
    story.append(Paragraph("<b>All Questions Asked During Investigation</b>", styles["Heading2"]))

    table_data = [["Question", "Agent","Result"]]
    for q in all_questions:
        question = q.get('question')
        agent_name = q.get('agent') if q.get('agent') is not None else "Null"
        result = q.get('result') if q.get('result') is not None else "Null"
        wrapped_questions = Paragraph(question, table_cell_style)
        wrapped_agent_name = Paragraph(agent_name, table_cell_style)
        wrapped_result = Paragraph(result, table_cell_style)
        table_data.append([[wrapped_questions], [wrapped_agent_name], [wrapped_result]])

    table = Table(table_data, colWidths=[350, 75, 75])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.orange),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(table)

    story.append(PageBreak())

    # ------------------------------------------------
    # Hypotheses Questions
    # ------------------------------------------------

    styles = getSampleStyleSheet()
    # Create a custom style for table cells if you want smaller text
    table_cell_style = styles["BodyText"]
    table_cell_style.wordWrap = 'CJK'
    story.append(Paragraph("<b>Questions per Hypothesis</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    table_data = [["Hypothesis", "Questions", "Agent","Result"]]
    for category, questions in data["questions"].items():
        for q in questions:
            question = q.get('question')
            agent_name = q.get('agent') if q.get('agent') is not None else "Null"
            result = q.get('result') if q.get('result') is not None else "Null"
            wrapped_hypothesis = Paragraph(category, table_cell_style)
            wrapped_questions = Paragraph(question, table_cell_style)
            wrapped_agent_name = Paragraph(agent_name, table_cell_style)
            wrapped_result = Paragraph(result, table_cell_style)
            table_data.append([[wrapped_hypothesis], [wrapped_questions], [wrapped_agent_name], [wrapped_result]])

    table = Table(table_data, colWidths=[100, 250, 75, 75])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.orange),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP")]))

    story.append(table)

    # ------------------------------------------------
    # Build PDF
    # ------------------------------------------------
    doc.build(story)

    return {
        "status": "success",
        "pdf_path": os.path.abspath(output_file)
    }


functions = {
    'generate_investigation_pdf': generate_investigation_pdf
}