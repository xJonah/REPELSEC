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
        self.severity = "Critical"
        self.url = ("https://cwe.mitre.org/data/definitions/89.html, "
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
        self.remediation_advice = ("Prepared statements, client and server side input validation, safe stored "
                                   "procedures, or escaping user input can be used to mitigate against SQL injection "
                                   "attacks. Refer to OWASP cheat sheet for examples.")

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
            "The product contains a hard-coded password, which it uses for its own inbound authentication or for "
            "outbound communication to external components.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/259.html"
        self.remediation_advice = "Passwords should be hashed and stored safely in a password-protected external file"

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(
            pattern="password=[\"']|pwd=[\"']|passwd=[\"']|pw=[\"']|pword=[\"']|pass=[\"']|passcode=[\"']",
            string=formatted_str, flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


# Use of Hard-coded Credentials
class CWE798:
    def __init__(self):
        self.id = "CWE-798"
        self.name = "Use of Hard-coded Credentials"
        self.description = ("The product contains hard-coded credentials, such as a password or cryptographic key, "
                            "which it uses for its own inbound authentication, outbound communication to external "
                            "components, or encryption of internal data.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/798.html"
        self.remediation_advice = "Credentials should be hashed and stored safely in a password-protected external file"

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(pattern="username=[\"']|uname=[\"']|id=[\"']|username=[\"']", string=formatted_str,
                                   flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


# Use of Hard-coded Cryptographic Key
class CWE321:
    def __init__(self):
        self.id = "CWE-321"
        self.name = "Use of Hard-coded Cryptographic Key"
        self.description = ("The use of a hard-coded cryptographic key significantly increases the possibility that "
                            "encrypted data may be recovered.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/321.html"
        self.remediation_advice = "Cryptographic keys should be stored safely in a password-protected external file"

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(pattern="key=[\"']|token=[\"']|encryption_key=[\"']|auth=[\"']|secret=[\"']",
                                   string=formatted_str, flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


# Inadequate Encryption Strength
class CWE326:
    def __init__(self):
        self.id = "CWE-326"
        self.name = "Inadequate Encryption Strength"
        self.description = ("The product stores or transmits sensitive data using an encryption scheme that is "
                            "theoretically sound, but is not strong enough for the level of protection required.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/326.html"
        self.remediation_advice = ""

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(pattern=r'newFile\("([^"]*)"\)',
                                   string=formatted_str, flags=re.IGNORECASE)

        if len(pattern_found) > 0:
            path = pattern_found[0]

            with open(path, "r") as f:
                token = f.readline()

            # Check the length of the token
            length_score = min(len(token) / 16.0, 1.0)

            # Check the complexity of characters (lowercase, uppercase, digits, symbols)
            lowercase = any(c.islower() for c in token)
            uppercase = any(c.isupper() for c in token)
            digits = any(c.isdigit() for c in token)
            symbols = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', token))

            complexity_score = sum([lowercase, uppercase, digits, symbols]) / 4.0

            # Combine scores and provide an overall strength assessment
            total_score = (length_score + complexity_score) / 2.0

            if total_score >= 0.75:
                return False
            else:
                return True
