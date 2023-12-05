import re


# Details from cwe.mitre.org

# 1 - SQL Injection
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
        print(formatted_str)
        pattern_found = re.findall(pattern="username=[\"']|password=[\"']|key=[\"']", string=formatted_str,
                                   flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


# Use of Hard-coded Credentials
class CWE798:
    id = "CWE-798"
    name = "Use of Hard-coded Credentials"
    description = ("The product contains hard-coded credentials, such as a password or cryptographic key, which it "
                   "uses for its own inbound authentication, outbound communication to external components, "
                   "or encryption of internal data.")
    severity = "Low"
    url = "https://cwe.mitre.org/data/definitions/798.html"


# Use of Hard-coded Cryptographic Key
class CWE321:
    id = "CWE-321"
    name = "Use of Hard-coded Cryptographic Key"
    description = ("The use of a hard-coded cryptographic key significantly increases the possibility that encrypted "
                   "data may be recovered.")
    severity = "Low"
    url = "https://cwe.mitre.org/data/definitions/321.html"
