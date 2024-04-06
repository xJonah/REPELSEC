# imports
from fpdf import FPDF
from datetime import date

# A4 - 210x297

# Variables
title = "REPELSEC"


class PDF(FPDF):
    def sast_header(self):

        # Title
        self.set_font('Arial', 'B', 15)
        self.set_text_color(255, 0, 0)
        self.set_x(10)  # Left
        self.cell(0, 0, title)

        # Date
        today = date.today()
        d1 = today.strftime("%d/%m/%Y")
        w = self.get_string_width(d1)
        self.set_x(200 - w)  # Right
        self.cell(0, 0, d1)

        # Line split
        self.set_draw_color(0, 255, 255)
        self.line(0, 20, 210, 20)

        # Scan Type
        scan_type = "SAST Report"
        w = self.get_string_width(scan_type)
        self.set_x((210 - w) / 2)  # Center
        self.cell(0, 0, scan_type)

        self.ln(20)

    def sca_header(self):
        # Title
        self.set_font('Arial', 'B', 15)
        self.set_text_color(255, 0, 0)
        self.set_x(10)  # Left
        self.cell(0, 0, title)

        # Date
        today = date.today()
        d1 = today.strftime("%d/%m/%Y")
        w = self.get_string_width(d1)
        self.set_x(200 - w)  # Right
        self.cell(0, 0, d1)

        # Line split
        self.set_draw_color(0, 255, 255)
        self.line(0, 20, 210, 20)

        # Scan Type
        scan_type = "SCA Report"
        w = self.get_string_width(scan_type)
        self.set_x((210 - w) / 2)  # Center
        self.cell(0, 0, scan_type)

        self.ln(20)

    def summary(self):
        pass

    def sca_vulnerabilities(self, vuln_list):
        self.set_font('Arial', 'B', 10)
        self.set_text_color(0, 0, 0)
        index = 0

        for vuln in vuln_list:
            index += 1

            self.multi_cell(0, 5, f"~~~~~~~~~~~~~~~ Vulnerability {index} ~~~~~~~~~~~~~~~")
            self.multi_cell(0, 5, f"ID - {vuln.get('ID')}")
            self.multi_cell(0, 5, f"Artifact - {vuln.get('Artifact')}")
            self.multi_cell(0, 5, f"Group - {vuln.get('Group')}")
            self.multi_cell(0, 5, f"Description - {vuln.get('Description')}")
            self.multi_cell(0, 5, f"Severity - {vuln.get('Severity')}")
            self.multi_cell(0, 5, f"CVSS - {vuln.get('CVSS')}")
            self.multi_cell(0, 5, f"Remediation Advice - {vuln.get('Remediation Advice')}")
            self.multi_cell(0, 5, f"Discovery Date - {vuln.get('Discovery Date')}")
            self.multi_cell(0, 5, f"Scan Date - {vuln.get('Scan Date')}")
            self.multi_cell(0, 5, f"Resources - {vuln.get('CVE References')}")
            self.multi_cell(0, 5, f"NVD Link - {vuln.get('NVD URL')}")
            self.multi_cell(0, 5, f"Days To Remediate - {vuln.get('Days To Remediate')}")
            self.ln(10)

    def sast_vulnerabilities(self, vuln_list):
        self.set_font('Arial', 'B', 10)
        self.set_text_color(0, 0, 0)
        index = 0

        for vuln in vuln_list:
            index += 1
            self.multi_cell(0, 5, f"~~~~~~~~~~~~~~~ Vulnerability {index} ~~~~~~~~~~~~~~~")
            self.multi_cell(0, 5, f"ID - {vuln.get('ID')}")
            self.multi_cell(0, 5, f"Module - {vuln.get('Module')} (Line {vuln.get("Line Number")})")
            self.multi_cell(0, 5, f"Name - {vuln.get('Name')}")
            self.multi_cell(0, 5, f"Description - {vuln.get('Description')}")
            self.multi_cell(0, 5, f"Severity - {vuln.get('Severity')}")
            self.multi_cell(0, 5, f"Resources - {vuln.get('URL')}")
            self.multi_cell(0, 5, f"Remediation Advice - {vuln.get('Remediation Advice')}")
            self.multi_cell(0, 5, f"Days To Remediate - {vuln.get('Days To Remediate')}")
            self.ln(10)

            if index % 4 == 0:
                self.add_page()

    def footer(self):
        self.set_font('Arial', 'B', 10)
        self.set_text_color(0, 0, 0)

        foot = "© REPELSEC"
        w = self.get_string_width(foot)
        self.set_xy((210 - w) / 2, 280)  # Center Bottom
        self.cell(0, 0, foot)

    def create_pdf(self, scan_type, vuln_list):
        self.add_page()

        if scan_type == "SCA":
            self.sca_header()
            self.sca_vulnerabilities(vuln_list)
        else:
            self.sast_header()
            self.sast_vulnerabilities(vuln_list)
