from fpdf import FPDF
from datetime import datetime

def generate_pdf_report(username, scan_results, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)

    # Header
    pdf.cell(0, 10, f"ExploitEye Scan Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"User: {username}", ln=True)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(10)

    # Results Section
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Scan Results:", ln=True)
    pdf.set_font("Arial", "", 12)
    for result in scan_results:
        pdf.multi_cell(0, 8, f"- {result['vuln']}:\n  {result['description']}\n  Mitigation: {result['mitigation']}")
        pdf.ln(2)

    # Save PDF
    pdf.output(filename)
    return filename
