import os
import re
from repelsec import cwe_vulnerabilities


# Function to check if path/file exists
def is_valid_path(parser, arg):
    if not os.path.exists(arg):
        parser.error(f"The file {arg} does not exist")
    else:
        return arg


# Function to find correct version string for dependency
def find_version(version, springboot_version, properties_dict):
    # Find correct area of pom.xml to read from
    if version is None:
        version_found = springboot_version
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
def find_vulnerability(line_str, vuln_object, sast_dict_list):
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
        }
        sast_dict_list.append(vulnerability_dict)

    return sast_dict_list


# Function to measure security score
def modify_scan_score(score, severity):
    if score <= 0:
        return 0
    elif score > 0 and severity == "Low":
        return score - 1
    elif score > 1 and severity == "Medium":
        return score - 2
    elif score > 4 and severity == "High":
        return score - 5
    elif score > 9 and severity == "Critical":
        return score - 10
    else:
        raise Exception("Unexpected score/severity value")
