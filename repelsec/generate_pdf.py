# imports
from fpdf import FPDF

# A4 - 210x297

# Variables
title = "REPELSEC"


class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(0, 0, 255)
        w = self.get_string_width(title)
        self.set_x((210 - w) / 2)
        self.cell(0, 0, title)
        self.ln(10)

    def summary(self):
        pass

    def sca_vulnerabilities(self, vuln_list):
        self.set_font('Arial', 'B', 10)
        index = 0

        for vuln in vuln_list:
            index += 1
            self.multi_cell(0, 5,
                            f"{index}) {vuln.get('ID')} ({vuln.get('Artifact')}")
            self.multi_cell(0, 5, f"Group - {vuln.get('Group')}")
            self.multi_cell(0, 5, f"Description - {vuln.get('Description')}")
            self.multi_cell(0, 5, f"Severity - {vuln.get('Severity')}")
            self.multi_cell(0, 5, f"CVSS - {vuln.get('CVSS')}")
            self.multi_cell(0, 5, f"Remediation Advice - {vuln.get('Remediation Advice')}")
            self.multi_cell(0, 5, f"Discovery Date - {vuln.get('Discovery Date')}")
            self.multi_cell(0, 5, f"Scan Date - {vuln.get('Scan Date')}")
            self.multi_cell(0, 5, f"Resources - {vuln.get('CVE References')}")
            self.multi_cell(0, 5, f"NVD Link - {vuln.get('NVD URL')}")
            self.ln(10)

    def sast_vulnerabilities(self, vuln_list):
        self.set_font('Arial', 'B', 10)
        index = 0

        for vuln in vuln_list:
            index += 1
            self.multi_cell(0, 5,
                            f"{index}) {vuln.get('ID')} ({vuln.get('Module')} - Line {str(vuln.get('Line Number'))})")
            self.multi_cell(0, 5, f"Name - {vuln.get('Name')}")
            self.multi_cell(0, 5, f"Description - {vuln.get('Description')}")
            self.multi_cell(0, 5, f"Severity - {vuln.get('Severity')}")
            self.multi_cell(0, 5, f"Resources - {vuln.get('URL')}")
            self.multi_cell(0, 5, f"Remediation Advice - {vuln.get('Remediation Advice')}")
            self.ln(10)

    def footer(self):
        pass

    def create_pdf(self, scan_type, vuln_list):
        self.add_page()

        if scan_type == "SCA":
            self.sca_vulnerabilities(vuln_list)
        else:
            self.sast_vulnerabilities(vuln_list)
