import re


# Details from cwe.mitre.org

# SQL Injection
class CWE89:
    def __init__(self):
        self.id = "CWE-89"
        self.name = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        self.description = (
            "The product constructs all or part of an SQL command using externally-influenced input from an "
            "upstream component, but it does not neutralize or incorrectly neutralizes special elements that "
            "could modify the intended SQL command when it is sent to a downstream component")
        self.severity = "Very High"
        self.url = "https://cwe.mitre.org/data/definitions/89.html"

    @staticmethod
    def scan(line_str):
        if "Statement" in line_str and "PreparedStatement" not in line_str:
            return True
        else:
            return False


# Use of Hard-coded Password
class CWE259:
    def __init__(self):
        self.id = "CWE-259"
        self.name = "Use of Hard-coded Password"
        self.description = (
            "The product contains a hard-coded password, which it uses for its own inbound authentication or"
            "for outbound communication to external components.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/259.html"

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(pattern="username=[\"']|password=[\"']|key=[\"']", string=formatted_str,
                                   flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False
