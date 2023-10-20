# Imports
from argparse import ArgumentParser, Namespace
import os.path
import nvdlib
import xmltodict
import pprint
import json
import pandas as pd
from datetime import datetime


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error(f"The file {arg} does not exist")
    else:
        return arg


def main():
    parser = ArgumentParser()

    # Arguments
    parser.add_argument("filename", help="Scans a given file", type=lambda x: is_valid_file(parser, x))
    parser.add_argument("-c", "--csv", help="Export results to a csv file", action="store_true")
    parser.add_argument("-p", "--pdf", help="Export results to a pdf file", action="store_true")

    args: Namespace = parser.parse_args()

    with open(args.filename, "r") as f:
        file = f.read()

    if "pom.xml" in args.filename:
        pom_dict = xmltodict.parse(file)

        parent = pom_dict["project"]["parent"]
        spring_version = parent.get("version")

        dependencies = pom_dict["project"]["dependencies"]["dependency"]

        with open("repelsec/java_cpe_dictionary.json", "r") as f:
            cpe_dict = json.load(f)

        sca_dict_list = []

        for dependency in dependencies:

            artifact = dependency.get("artifactId")
            group = dependency.get("groupID")

            if dependency.get("version") is not None:  # need regex improvement
                version = dependency.get("version")
            else:
                version = spring_version

            cpe = cpe_dict.get(artifact)

            if cpe is not None:
                formatted_cpe = cpe.replace("*", version, 1)

                cve_list = nvdlib.searchCVE(cpeName="cpe:2.3:a:apache:commons_io:2.6:-:*:*:*:*:*:*", limit=10)
                # cve_list = nvdlib.searchCVE(cpeName=formatted_cpe, limit=10)

                for cve in cve_list:
                    published_date_object = datetime.strptime(cve.published, "%Y-%m-%dT%H:%M:%S.%f")
                    published_date = published_date_object.strftime("%d/%m/%Y")

                    current_date_object = datetime.now()
                    current_date = current_date_object.strftime("%d/%m/%Y")

                    sca_temp_dict = {
                        "ID": cve.id,  # CVE Number
                        "Artifact": artifact,  # Dependency Artifact
                        "Group": group,  # Dependency Group
                        "Description": cve.descriptions[0].value,  # English Description
                        "Severity": cve.score[2],  # Severity (Low - Critical)
                        "CVSS": cve.score[1],  # Latest CVSS Score (V2 - V3.1)
                        "Discovery Date": published_date,  # Date NVD published CVE
                        "Remediation Advice": "Update dependency to latest secure version or switch "
                                              "to a secure alternative library",
                        "Scan Date": current_date,  # Date of REPELSEC scan
                        "NVD URL": cve.url,  # NIST CVE URL
                    }
                    
                    sca_dict_list.append(sca_temp_dict)

        if args.csv:
            df = pd.DataFrame.from_records(sca_dict_list)
            df.to_csv("repelsec/sca.csv", index=False)
