import re

from repelsec.functions import is_strong_token


# MITRE CWE Classes:

# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
# CWE-111: Direct Use of Unsafe JNI
# CWE-190: Integer Overflow or Wraparound
# CWE-191: Integer Underflow (Wrap or Wraparound)
# CWE-209: Generation of Error Message Containing Sensitive Information
# CWE-246: J2EE Bad Practices: Direct Use of Sockets
# CWE-259: Use of Hard-coded Password
# CWE-321: Use of Hard-coded Cryptographic Key
# CWE-326: Inadequate Encryption Strength
# CWE-382: J2EE Bad Practices: Use of System.exit()
# CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference
# CWE-396: Declaration of Catch for Generic Exception
# CWE-397: Declaration of Throws for Generic Exception
# CWE-481: Assigning instead of Comparing
# CWE-491: Public cloneable() Method Without Final ('Object Hijack')
# CWE-493: Critical Public Variable Without Final Modifier
# CWE-500: Public Static Field Not Marked Final
# CWE-572: Call to Thread run() instead of start()
# CWE-582: Array Declared Public, Final, and Static
# CWE-583: finalize() Method Declared Public
# CWE-585: Empty Synchronized Block
# CWE-586: Explicit Call to Finalize()
# CWE-595: Comparison of Object References Instead of Object Contents
# CWE-766: Critical Data Element Declared Public
# CWE-798: Use of Hard-coded Credentials


class CWE89:
    def __init__(self):
        self.id = "CWE-89"
        self.name = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        self.description = (
            "The product constructs all or part of an SQL command using externally-influenced input from an "
            "upstream component, but it does not neutralize or incorrectly neutralizes special elements that "
            "could modify the intended SQL command when it is sent to a downstream component")
        self.severity = "Critical"
        self.url = "https://cwe.mitre.org/data/definitions/89.html"
        self.remediation_advice = ("Prepared statements, client and server side input validation, safe stored "
                                   "procedures, or escaping user input can be used to mitigate against SQL injection "
                                   "attacks.")
        self.remediation_days = 15

    @staticmethod
    def scan(line_str):
        if "Statement" in line_str and "PreparedStatement" not in line_str and "prepareStatement" not in line_str:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(pattern=r"(public|protected|private) native", string=line_str)

        if pattern_found:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):

        pattern_found = re.findall(pattern=r"int (. *) = Integer.MAX_VALUE \+", string=line_str)

        if pattern_found:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):

        pattern_found = re.findall(pattern=r"int(. *) = Integer.MIN_VALUE \-", string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE209:
    def __init__(self):
        self.id = "CWE-209"
        self.name = "Generation of Error Message Containing Sensitive Information"
        self.description = (
            "The product generates an error message that includes sensitive information about its environment, users, or associated data.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/209.html"
        self.remediation_advice = "When an exception is caught, only print insensitive and desired data to a user."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        if "catch" in line_str and "Exception e" in line_str:
            if "System.out.println(e)" in line_str or "e.printStackTrace()" in line_str:
                return True

        return False


class CWE246:
    def __init__(self):
        self.id = "CWE-246"
        self.name = "J2EE Bad Practices: Direct Use of Sockets"
        self.description = "The J2EE application directly uses sockets instead of using framework method calls."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/246.html"
        self.remediation_advice = "Use framework method calls instead of using sockets directly."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):

        pattern_found = re.findall(pattern=r"(?<=Socket )(.*)(?=null;)", string=line_str)

        if pattern_found:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(
            pattern=r"password=[\"']|pwd=[\"']|passwd=[\"']|pw=[\"']|pword=[\"']|pass=[\"']|passcode=[\"']",
            string=formatted_str, flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


class CWE321:
    def __init__(self):
        self.id = "CWE-321"
        self.name = "Use of Hard-coded Cryptographic Key"
        self.description = ("The use of a hard-coded cryptographic key significantly increases the possibility that "
                            "encrypted data may be recovered.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/321.html"
        self.remediation_advice = "Cryptographic keys should be stored safely in a password-protected external file"
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(
            pattern=r"key=[\"']|token=[\"']|encryption_key=[\"']|auth=[\"']|secret=[\"']|encryption=[\"']",
            string=formatted_str, flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(
            pattern=r'newFile\("(.*?(?:token|key|secret|auth|encryption_key|encryption).*?)"\)',
            string=formatted_str, flags=re.IGNORECASE)

        if pattern_found:
            path = pattern_found[0]

            with open(path, "r") as f:
                token = f.readline()

                return is_strong_token(token)


class CWE382:
    def __init__(self):
        self.id = "CWE-382"
        self.name = "J2EE Bad Practices: Use of System.exit()"
        self.description = "A J2EE application uses System.exit(), which also shuts down its container."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/382.html"
        self.remediation_advice = ("Shutdown function should be a privileged function only available to an authorised "
                                   "administrative user. Web applications should not call System.exit() as it can "
                                   "cause the virtual machine to exit.")
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):

        pattern_found = re.findall(pattern=r"System.exit\((-1|0|1)\);", string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE395:
    def __init__(self):
        self.id = "CWE-395"
        self.name = "Use of NullPointerException Catch to Detect NULL Pointer Dereference"
        self.description = ("Catching NullPointerException should not be used as an alternative to programmatic checks "
                            "to prevent de-referencing a null pointer.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/395.html"
        self.remediation_advice = (
            "Do not extensively rely on catching exceptions (especially for validating user input) to handle errors. "
            "Handling exceptions can decrease the performance of an application.")
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        if "catch(NullPointerException" in formatted_str:
            return True
        else:
            return False


class CWE396:
    def __init__(self):
        self.id = "CWE-396"
        self.name = "Declaration of Catch for Generic Exception"
        self.description = (
            "Catching overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/396.html"
        self.remediation_advice = "Define specific exceptions and use multiple catch blocks if necessary."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        if "catch(Exception" in formatted_str:
            return True
        else:
            return False


class CWE397:
    def __init__(self):
        self.id = "CWE-397"
        self.name = "Declaration of Throws for Generic Exception"
        self.description = (
            "Throwing overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.")
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/397.html"
        self.remediation_advice = "Define the specific exceptions that should be thrown."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        if "throws Exception" in line_str:
            return True
        else:
            return False


class CWE481:
    def __init__(self):
        self.id = "CWE-481"
        self.name = "Assigning instead of Comparing"
        self.description = "The code uses an operator for assignment when the intention was to perform a comparison."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/481.html"
        self.remediation_advice = "Check operator used is correct. For example == is used for comparison and = is used for assignment."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")

        pattern_found = re.findall(pattern=r"if\(([a-zA-Z0-9]*)=[^=](true|false|(\d*))", string=formatted_str)

        if pattern_found:
            return True
        else:
            return False


class CWE491:
    def __init__(self):
        self.id = "CWE-491"
        self.name = "Public cloneable() Method Without Final ('Object Hijack')"
        self.description = "A class has a cloneable() method that is not declared final, which allows an object to be created without calling the constructor. This can cause the object to be in an unexpected state."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/491.html"
        self.remediation_advice = "Make the cloneable() method final."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(pattern=r"(public|protected|private) Object clone\(", string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE493:
    def __init__(self):
        self.id = "CWE-493"
        self.name = "Critical Public Variable Without Final Modifier"
        self.description = "The product has a critical public variable that is not final, which allows the variable to be modified to contain unexpected values."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/493.html"
        self.remediation_advice = "Declare all public fields as final when possible, especially if it is used to maintain internal state of an Applet or of classes used by an Applet. If a field must be public, then perform all appropriate sanity checks before accessing the field from your code."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(
            pattern=r"public (byte|short|long|double|String|float|int|char|boolean|BigDecimal) (price|path|balance)",
            string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE500:
    def __init__(self):
        self.id = "CWE-500"
        self.name = "Public Static Field Not Marked Final"
        self.description = "An object contains a public static field that is not marked final, which might allow it to be modified in unexpected ways."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/500.html"
        self.remediation_advice = "Clearly identify the scope for all critical data elements, including whether they should be regarded as static. Make any static fields private and constant."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(
            pattern=r"(public|private|protected) static (byte|short|long|double|String|float|int|char|boolean|BigDecimal)",
            string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE572:
    def __init__(self):
        self.id = "CWE-572"
        self.name = "Call to Thread run() instead of start()"
        self.description = "The product calls a thread's run() method instead of calling start(), which causes the code to run in the thread of the caller instead of the callee."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/572.html"
        self.remediation_advice = "Use the start() method instead of the run() method."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(
            pattern=r"(thr|thread).run\(\)", string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE582:
    def __init__(self):
        self.id = "CWE-582"
        self.name = "Array Declared Public, Final, and Static"
        self.description = "The product declares an array public, final, and static, which is not sufficient to prevent the array's contents from being modified."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/582.html"
        self.remediation_advice = "The array should be made private."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(
            pattern=r"public final static (.*)\[\] (.*);", string=line_str)

        if pattern_found:
            return True
        else:
            return False


class CWE583:
    def __init__(self):
        self.id = "CWE-583"
        self.name = "finalize() Method Declared Public"
        self.description = "The product violates secure coding principles for mobile code by declaring a finalize() method public."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/583.html"
        self.remediation_advice = "If you are using finalize() as it was designed, there is no reason to declare finalize() with anything other than protected access."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        if "public void finalize()" in line_str or "private void finalize()" in line_str:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")

        if "synchronized(this){}" in formatted_str:
            return True
        else:
            return False


class CWE586:
    def __init__(self):
        self.id = "CWE-586"
        self.name = "Explicit Call to Finalize()"
        self.description = "The product makes an explicit call to the finalize() method from outside the finalizer."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/586.html"
        self.remediation_advice = "Do not make explicit calls to finalize()."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        if ".finalize()" in line_str and "this.finalize()" not in line_str:
            return True
        else:
            return False


class CWE595:
    def __init__(self):
        self.id = "CWE-595"
        self.name = "Comparison of Object References Instead of Object Contents"
        self.description = "The product compares object references instead of the contents of the objects themselves, preventing it from detecting equivalent objects"
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/595.html"
        self.remediation_advice = "The equals() method should be used used to compare objects instead of =="
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")

        pattern_found = re.findall(pattern=r"if\((.*)==\"(.*)\"\)", string=formatted_str)

        if pattern_found:
            return True
        else:
            return False


class CWE766:
    def __init__(self):
        self.id = "CWE-766"
        self.name = "Critical Data Element Declared Public"
        self.description = "The product declares a critical variable, field, or member to be public when intended security policy requires it to be private."
        self.severity = "Low"
        self.url = "https://cwe.mitre.org/data/definitions/766.html"
        self.remediation_advice = "Data should be private, static, and final whenever possible. This will assure that your code is protected by instantiating early, preventing access, and preventing tampering."
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        pattern_found = re.findall(
            pattern=r"public(static |final | )(byte|short|long|double|String|float|int|char|boolean|BigDecimal) (username|password)",
            string=line_str, flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False


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
        self.remediation_days = 120

    @staticmethod
    def scan(line_str):
        formatted_str = line_str.replace(" ", "")
        pattern_found = re.findall(pattern=r"username=[\"']|uname=[\"']|id=[\"']|user=[\"']", string=formatted_str,
                                   flags=re.IGNORECASE)

        if pattern_found:
            return True
        else:
            return False
