# Imports
from argparse import ArgumentParser, Namespace
import os.path
import nvdlib
import xmltodict
import json
import pandas as pd
from datetime import datetime
import re


# Function to check if path/file exists
def is_valid_file(parser, arg):
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


def main():
    parser = ArgumentParser()

    # CLI Arguments
    parser.add_argument("filename", help="Scans a given file", type=lambda x: is_valid_file(parser, x))
    parser.add_argument("-c", "--csv", help="Export results to a csv file", action="store_true")
    parser.add_argument("-p", "--pdf", help="Export results to a pdf file", action="store_true")

    args: Namespace = parser.parse_args()

    # Open supplied file
    with open(args.filename, "r") as f:
        file = f.read()

    # SCA scan
    if "pom.xml" in args.filename:
        pom_dict = xmltodict.parse(file)

        parent = pom_dict["project"]["parent"]
        spring_version = parent.get("version")
        dependencies = pom_dict["project"]["dependencies"]["dependency"]
        properties = pom_dict["project"]["properties"]

        # print(properties)

        with open("repelsec/java_cpe_dictionary.json", "r") as f:
            cpe_dict = json.load(f)

        sca_dict_list = []

        for dependency in dependencies:

            artifact = dependency.get("artifactId")
            group = dependency.get("groupId")
            artifact_version = dependency.get("version")
            version = find_version(artifact_version, spring_version, properties)

            cpe = cpe_dict.get(artifact)

            if cpe is not None:
                formatted_cpe = cpe.replace("*", version, 1)

                cve_list = nvdlib.searchCVE(cpeName=formatted_cpe, limit=100)

                for cve in cve_list:
                    cve_id = cve.id
                    description = cve.descriptions[0].value
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

                    sca_temp_dict = {
                        "ID": cve_id,  # CVE Number
                        "Artifact": f"{artifact} {version}",  # Dependency Artifact
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

                    # print(sca_temp_dict)
                    sca_dict_list.append(sca_temp_dict)

                    if args.csv:
                        df = pd.DataFrame.from_records(sca_dict_list)
                        df.to_csv("repelsec/sca.csv", index=False)

    # SAST Scan
    elif ".java" in args.filename:

        # Check for hardcoded passwords/api keys etc...

        pass
