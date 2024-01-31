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
        pattern_found = re.findall(
            pattern="key=[\"']|token=[\"']|encryption_key=[\"']|auth=[\"']|secret=[\"']|encryption=[\"']",
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
        self.remediation_advice = ("Use trusted libraries/APIs that create encryption keys using best practices "
                                   "or define long, complex strings with a variety of letters, digits, upper and "
                                   "lowercase, and special characters.")

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(
            pattern=r'newFile\("([^"]*)\/([^"]*)(token|key|secret|auth|encryption_key|encryption)([^"]*)"\)',
            string=formatted_str, flags=re.IGNORECASE)

        if pattern_found:
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


# Empty Synchronized Block
class CWE585:
    def __init__(self):
        self.id = "CWE-585"
        self.name = "Empty Synchronized Block"
        self.description = ("An empty synchronized block does not actually accomplish any synchronization and may "
                            "indicate a troubled section of code. An empty synchronized block can occur because code "
                            "no longer needed within the synchronized block is commented out without removing the "
                            "synchronized block.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/585.html"
        self.remediation_advice = ("Remove empty synchronised block or define procedures that access or modify data "
                                   "that is exposed to multiple threads")

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(pattern="synchronized(this){}", string=formatted_str)

        if pattern_found:
            return True
        else:
            return False


# Potential for unsafe JNI
class CWE111:
    def __init__(self):
        self.id = "CWE-111"
        self.name = "Direct Use of Unsafe JNI"
        self.description = (
            "When a Java application uses the Java Native Interface (JNI) to call code written in another programming "
            "language, it can expose the application to weaknesses in that code, even if those weaknesses cannot "
            "occur in Java.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/111.html"
        self.remediation_advice = ("Implement error handling around JNI call; do not use JNI calls if native "
                                   "library is not trusted; use Java API equivalents if they exist")

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(pattern="public|protected|private native", string=line_str)

        if pattern_found:
            return True
        else:
            return False


# Integer Overflow
class CWE190:
    def __init__(self):
        self.id = "CWE-190"
        self.name = "Integer Overflow or Wraparound"
        self.description = (
            "An integer overflow or wraparound occurs when an integer value is incremented to a value that is too "
            "large to store in the associated representation. When this occurs, the value may wrap to "
            "become a very small or negative number.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/190.html"
        self.remediation_advice = ("Implement exception handling; use another data type such as Long or "
                                   "BigInteger if performing operations close to the maximum of an Integer")

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")

        if "Integer.MAX_VALUE+" or "2147483647+" in formatted_str:
            return True
        else:
            return False


# Integer Underflow
class CWE191:
    def __init__(self):
        self.id = "CWE-191"
        self.name = "Integer Underflow (Wrap or Wraparound)"
        self.description = ("The product subtracts one value from another, such that the result is less than the "
                            "minimum allowable integer value, which produces a value that is not equal to the "
                            "correct result.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/191.html"
        self.remediation_advice = ("Implement exception handling; use another data type such as Long or "
                                   "BigInteger if performing operations close to the minimum of an Integer")

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")

        if "Integer.MIN_VALUE-" or "-2147483648-" in formatted_str:
            return True
        else:
            return False


# Generation of Error Message Containing Sensitive Information
class CWE209:
    def __init__(self):
        self.id = "CWE-209"
        self.name = "Generation of Error Message Containing Sensitive Information"
        self.description = (
            "The product generates an error message that includes sensitive information about its environment, users, or associated data.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/209.html"
        self.remediation_advice = "When an exception is caught, only print insensitive and desired data to a user."

    @staticmethod
    def scan(line_str):
        if "catch" in line_str and "Exception e" in line_str:
            if "System.out.println(e)" in line_str or "e.printStackTrace()" in line_str:
                return True

        return False
