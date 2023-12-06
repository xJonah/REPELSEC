# Imports
import os
import re
from argparse import ArgumentParser, Namespace
import nvdlib
import xmltodict
import json
import pandas as pd
from datetime import datetime
from repelsec import functions as sec


def main():
    # Instantiate argument parser object
    parser = ArgumentParser()

    # Define CLI Arguments
    parser.add_argument("filename", help="Scans a given file", type=lambda x: sec.is_valid_path(parser, x))
    parser.add_argument("-c", "--csv", help="Export results to a csv file", action="store_true")
    parser.add_argument("-p", "--pdf", help="Export results to a pdf file", action="store_true")
    parser.add_argument("-t", "--txt", help="Export results to a txt file", action="store_true")
    parser.add_argument("-o", "--output_path", help="Output to chosen directory",
                        type=lambda x: sec.is_valid_path(parser, x))

    # Define custom type
    args: Namespace = parser.parse_args()

    # Set output path for result exports
    if args.output_path is None:
        output_path = os.getcwd()
    else:
        output_path = args.output_path

    # SCA SCAN
    if "pom.xml" in args.filename:

        # Open supplied file
        with open(args.filename, "r") as f:
            file = f.read()

        # Convert XML file to Python Dictionary and assign its attributes to variables
        pom_dict = xmltodict.parse(file)
        parent = pom_dict["project"]["parent"]
        spring_version = parent.get("version")
        dependencies = pom_dict["project"]["dependencies"]["dependency"]
        properties = pom_dict["project"]["properties"]

        # Load NVD CPE Dictionary
        with open("repelsec/cpe_dictionary.json", "r") as f:
            cpe_dict = json.load(f)

        # Define empty list to store dictionaries of results
        sca_dict_list = []

        # Define NVD Key
        with open("repelsec/config/config.txt", "r") as f:
            nvd_key = f.readline()

        # Define loop counter
        vulnerability_number = 0

        # Iterates through pom.xml dependencies
        for dependency in dependencies:

            # Assign dependency attributes to variables
            artifact = dependency.get("artifactId")
            group = dependency.get("groupId")
            artifact_version = dependency.get("version")
            version = sec.find_version(artifact_version, spring_version, properties)

            # Match artifact with CPE dictionary
            cpe = cpe_dict.get(artifact)

            # If vulnerability exists in CPE
            if cpe is not None:
                # Define CPE with Artifact version
                formatted_cpe = cpe.replace("*", version, 1)

                # Search NVD database for CVEs assigned to the CPE
                cve_list = nvdlib.searchCVE(cpeName=formatted_cpe, limit=100)

                # Extract and define desired scan & CVE attributes
                for cve in cve_list:
                    cve_id = cve.id
                    description_array = cve.descriptions[0].value.split()
                    description = " ".join(description_array)
                    severity = cve.score[2]
                    cvss_score = cve.score[1]
                    remediation_action = "Upgrade dependency, implement mitigation, or use secure alternative"
                    cve_url = cve.url
                    published_date_object = datetime.strptime(cve.published, "%Y-%m-%dT%H:%M:%S.%f")
                    published_date = published_date_object.strftime("%d/%m/%Y")
                    current_date_object = datetime.now()
                    current_date = current_date_object.strftime("%d/%m/%Y")
                    cve_references = [x.url for x in cve.references]
                    cve_references_str = ", ".join(cve_references)
                    formatted_artifact = f"{artifact} {version}"
                    vulnerability_number += 1

                    # Create temp dictionary for each loop
                    sca_temp_dict = {
                        "ID": cve_id,  # CVE Number
                        "Artifact": formatted_artifact,  # Dependency Artifact
                        "Group": group,  # Dependency Group
                        "Description": description,  # English Description
                        "Severity": severity,  # Severity (Low - Critical)
                        "CVSS": cvss_score,  # Latest CVSS Score (V2 - V3.1)
                        "Remediation Advice": remediation_action,
                        "Discovery Date": published_date,  # Date NVD published CVE
                        "Scan Date": current_date,  # Date of REPELSEC scan
                        "CVE References": cve_references_str,
                        "NVD URL": cve_url,  # NIST CVE URL
                    }

                    # Append temp dictionary to main dictionary
                    sca_dict_list.append(sca_temp_dict)

                    # Print results to terminal
                    print(
                        f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  VULNERABILITY {vulnerability_number}  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    print(f"ID - {cve_id}")
                    print(f"Artifact - {formatted_artifact}")
                    print(f"Group - {group}")
                    print(f"Description - {description}")
                    print(f"Severity - {severity}")
                    print(f"CVSS - {cvss_score}")
                    print(f"Remediation Advice - {remediation_action}")
                    print(f"Discovery Date - {published_date}")
                    print(f"Scan Date - {current_date}")
                    print(f"CVE References - {cve_references_str}")
                    print(f"NVD URL - {cve_url}")
                    print("\n")

        # If csv argument is enabled, print SCA results to a csv file
        if args.csv:
            df = pd.DataFrame.from_records(sca_dict_list)
            df.to_csv(os.path.join(output_path, "sca.csv"), index=False)

        # If txt argument is enabled, print SCA results to a txt file
        if args.txt:
            with open(os.path.join(output_path, "sca.txt"), "w") as f:
                vuln_index = 0

                for vuln in sca_dict_list:
                    vuln_index += 1

                    f.write(
                        f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  VULNERABILITY {vuln_index}  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                    f.write(f"ID - {vuln.get('ID')}\n")
                    f.write(f"Artifact - {vuln.get('Artifact')}\n")
                    f.write(f"Group - {vuln.get('Group')}\n")
                    f.write(f"Description - {vuln.get('Description')}\n")
                    f.write(f"Severity - {vuln.get('Severity')}\n")
                    f.write(f"CVSS - {vuln.get('CVSS')}\n")
                    f.write(f"Remediation Advice - {vuln.get('Remediation Advice')}\n")
                    f.write(f"Discovery Date - {vuln.get('Discovery Date')}\n")
                    f.write(f"Scan Date - {vuln.get('Scan Date')}\n")
                    f.write(f"CVE References - {vuln.get('CVE References')}\n")
                    f.write(f"NVD URL - {vuln.get('NVD URL')}\n")
                    f.write("\n")

    # SAST Scan
    elif ".java" in args.filename:
        # Open supplied file
        with open(args.filename, "r") as f:
            lines = f.readlines()
            line_number = 0

            # Empty list created to store dictionaries of results
            sast_dict_list = []

            # For each line of source code, run vulnerability scan
            for line in lines:
                line_number += 1

                sec.find_vulnerability(line, 89, sast_dict_list, line_number)  # SQL injection scan
                sec.find_vulnerability(line, 259, sast_dict_list, line_number)  # Hard coded credentials scan

        print(sast_dict_list)

        # If csv argument is enabled, print SAST results to a csv file
        if args.csv:
            df = pd.DataFrame.from_records(sast_dict_list)
            df.to_csv(os.path.join(output_path, "sast.csv"), index=False)
