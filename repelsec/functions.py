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
def find_vulnerability(line_str, cwe_number, sast_dict_list, line_number):
    vulnerability = f"CWE{cwe_number}"
    vulnerability_object = getattr(cwe_vulnerabilities, vulnerability)
    vulnerability_test = vulnerability_object.scan(line_str)

    if vulnerability_test is True:
        vulnerability_dict = vulnerability_object().__dict__
        vulnerability_dict |= {"line_number": line_number}
        sast_dict_list.append(vulnerability_dict)

    return sast_dict_list
