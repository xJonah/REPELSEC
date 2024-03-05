import os
import re
import PyPDF2


# Function to check if path/file exists
def is_valid_path(parser, arg):
    if not os.path.exists(arg):
        parser.error(f"The file {arg} does not exist")
    else:
        return arg


# Function to find correct version string for dependencies
def find_version(version, springboot_version, properties_dict):
    # If no version defined for dependency, use springboot version
    if version is None:
        version_found = springboot_version
    # If dependency version is variable, get version from properties section
    elif version.startswith("$"):
        property_version = version[version.find("{") + 1:version.find("}")]
        version_found = properties_dict.get(property_version)
    else:
        version_found = version

    # Remove all characters except "." and [0-9]
    version_found = re.sub(r"[^0-9.]", "", str(version_found))

    if version_found.endswith("."):
        version_found = version_found[:-1]

    return version_found


# Function to find vulnerability, scan for vulnerability, and append result to list and return it
def find_vulnerability(line_str, vuln_object, sast_dict_list, line_number):
    vulnerability_test = vuln_object.scan(line_str)

    if vulnerability_test is True:
        obj = vuln_object()
        vulnerability_dict = {
            "ID": obj.id,
            "Name": obj.name,
            "Description": obj.description,
            "Severity": obj.severity,
            "URL": obj.url,
            "Remediation Advice": obj.remediation_advice,
            "Line Number": line_number,
            "Days To Remediate": obj.remediation_days
        }
        sast_dict_list.append(vulnerability_dict)

    return sast_dict_list


# Function to measure security score
def modify_scan_score(score, severity):
    match severity:
        case "Low":
            return max(score - 1, 0)
        case "Medium":
            return max(score - 2, 0)
        case "High":
            return max(score - 5, 0)
        case "Critical":
            return max(score - 10, 0)
        case _:
            raise Exception("Unexpected severity value")


# Function to return NIST recommended days to remediate
def get_remediation_days(severity):
    match severity:
        case "Low":
            return 120
        case "Medium":
            return 90
        case "High":
            return 30
        case "Critical":
            return 15
        case _:
            raise Exception("Unexpected severity value")


# Check for valid password encryption
def is_valid_password(parser, x):
    regex = re.compile(
        r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-])[A-Za-z\d!@#$%^&*()_+{}\[\]:;<>,'
        r'.?~\\/-]{8,}$',
        re.VERBOSE)

    if bool(regex.match(x)):
        return x
    else:
        parser.error(
            "Password must be a minimum of 8 characters and contain an uppercase, a lowercase, a special character, "
            "and a digit")


# Function to password-protect PDF report if argument enabled
def add_pdf_password(temp_path, output_path, password):
    with open(temp_path, "rb") as f:
        pdf_reader = PyPDF2.PdfReader(f)
        pdf_writer = PyPDF2.PdfWriter()

        for page_num in range(len(pdf_reader.pages)):
            pdf_writer.add_page(pdf_reader.pages[page_num])

        pdf_writer.encrypt(password)

        with open(output_path, "wb") as output_f:
            pdf_writer.write(output_f)

    os.remove(temp_path)
