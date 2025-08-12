import unittest

from repelsec import cwe_vulnerabilities
from repelsec.functions import *


class TestFunctions(unittest.TestCase):
    if __name__ == '__main__':
        unittest.main()

    def test_valid_path_function(self):

        valid_path1 = r"C:\Users\Jonah\Documents\GitHub\REPELSEC\Testing Resources\secure.java"
        valid_path2 = r"C:/Users/Jonah/Documents/GitHub/REPELSEC/Testing Resources/secure.java"
        invalid_path1 = r"C:\Users\Jonah\REPELSEC\Testing Resources\secure.java"
        invalid_path2 = r"Users/Jonah/Documents/GitHub/REPELSEC/Testing Resources/secure.java"

        self.assertTrue(os.path.exists(valid_path1))
        self.assertTrue(os.path.exists(valid_path2))
        self.assertFalse(os.path.exists(invalid_path1))
        self.assertFalse(os.path.exists(invalid_path2))

    def test_security_score_function(self):
        score = 100
        score = modify_scan_score(score, "Low")
        self.assertEqual(score, 99)
        score = modify_scan_score(score, "Medium")
        self.assertEqual(score, 97)
        score = modify_scan_score(score, "High")
        self.assertEqual(score, 92)
        score = modify_scan_score(score, "Critical")
        self.assertEqual(score, 82)

        vuln_severities = ["Critical", "Critical", "Critical", "Critical", "Critical", "Critical", "Critical",
                           "Critical", "Critical", "Critical", "Critical", "Critical", ]

        for severity in vuln_severities:
            score = modify_scan_score(score, severity)

        self.assertEqual(score, 0)

        with self.assertRaises(Exception):
            modify_scan_score(score, "Insane")

    def test_get_remediation_days_function(self):
        result = get_remediation_days("Low")
        self.assertEqual(result, 120)
        result = get_remediation_days("Medium")
        self.assertEqual(result, 90)
        result = get_remediation_days("High")
        self.assertEqual(result, 30)
        result = get_remediation_days("Critical")
        self.assertEqual(result, 15)

        with self.assertRaises(Exception):
            get_remediation_days("Insane")

    def test_valid_password_function(self):
        regex = re.compile(
            r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-])[A-Za-z\d!@#$%^&*()_+{}\[\]:;<>,'
            r'.?~\\/-]{8,}$',
            re.VERBOSE)

        valid_pass1 = "StrongPassword123^"
        valid_pass2 = "AWOdjoiwjdoiawjdoijwIOD1237879523!^@#"
        invalid_pass1 = "password"
        invalid_pass2 = "Aston123"
        self.assertTrue(regex.match(valid_pass1))
        self.assertTrue(regex.match(valid_pass2))
        self.assertFalse(regex.match(invalid_pass1))
        self.assertFalse(regex.match(invalid_pass2))


class TestSastScans(unittest.TestCase):

    def test_cwe89_scan(self):
        cwe89_obj = getattr(cwe_vulnerabilities, "CWE89")

        secure_string = "PreparedStatement stmt = ..."
        insecure_string = "Statement stmt = ..."
        self.assertFalse(cwe89_obj.scan(secure_string))
        self.assertTrue(cwe89_obj.scan(insecure_string))

    def test_cwe111_scan(self):
        cwe111_obj = getattr(cwe_vulnerabilities, "CWE111")

        insecure_string1 = "public native function"
        insecure_string2 = "private native function"
        insecure_string3 = "protected native function"

        self.assertTrue(cwe111_obj.scan(insecure_string1))
        self.assertTrue(cwe111_obj.scan(insecure_string2))
        self.assertTrue(cwe111_obj.scan(insecure_string3))

    # def test_cwe190_scan(self):
    #     cwe190_obj = getattr(cwe_vulnerabilities, "CWE190")
    #
    # def test_cwe191_scan(self):
    #     cwe191_obj = getattr(cwe_vulnerabilities, "CWE191")

    def test_cwe209_scan(self):
        cwe209_obj = getattr(cwe_vulnerabilities, "CWE209")

        secure_string = "catch (SQLException e) { System.out.println('Wrong credentials provided'); }"
        insecure_string1 = "catch (SQLException e) { System.out.println(e); }"
        insecure_string2 = "catch (SQLException e) { e.printStackTrace(); }"

        self.assertFalse(cwe209_obj.scan(secure_string))
        self.assertTrue(cwe209_obj.scan(insecure_string1))
        self.assertTrue(cwe209_obj.scan(insecure_string2))

    def test_cwe246_scan(self):
        cwe246_obj = getattr(cwe_vulnerabilities, "CWE246")

        secure_string = "Socket sock = new Socket(host, 6000);"
        insecure_string = "Socket sock = null;"

        self.assertFalse(cwe246_obj.scan(secure_string))
        self.assertTrue(cwe246_obj.scan(insecure_string))

    def test_cwe259_scan(self):
        cwe259_obj = getattr(cwe_vulnerabilities, "CWE259")

        secure_string = "private static final String PASSWORD = readLine();"
        insecure_string1 = "public static final String PASSWORD = 'password123';"
        insecure_string2 = 'private String pass = "password55";'

        self.assertFalse(cwe259_obj.scan(secure_string))
        self.assertTrue(cwe259_obj.scan(insecure_string1))
        self.assertTrue(cwe259_obj.scan(insecure_string2))

    def test_cwe321_scan(self):
        cwe321_obj = getattr(cwe_vulnerabilities, "CWE321")

        secure_string = "public static final String KEY = readLine();"
        insecure_string1 = "public static final String KEY = 'keyABC123';"
        insecure_string2 = "public String token = '7d82e94f95b6a2c9e8f4d5b7a80e6c3a';"

        self.assertFalse(cwe321_obj.scan(secure_string))
        self.assertTrue(cwe321_obj.scan(insecure_string1))
        self.assertTrue(cwe321_obj.scan(insecure_string2))

    def test_cwe326_scan(self):
        secure_string1 = "7d82e94f95b6a2c9e8f4d5b7a80e6c3a"
        secure_string2 = "AJDLWAJDAIWJjiwadjiaowdj22347982-1283749234##@"
        insecure_string1 = "tokenABC123"
        insecure_string2 = "abcdefghijklmnop"

        self.assertFalse(is_strong_token(secure_string1))
        self.assertFalse(is_strong_token(secure_string2))
        self.assertTrue(is_strong_token(insecure_string1))
        self.assertTrue(is_strong_token(insecure_string2))

    def test_cwe382_scan(self):
        cwe382_obj = getattr(cwe_vulnerabilities, "CWE382")

        insecure_string1 = "System.exit(-1);"
        insecure_string2 = "System.exit(0);"
        insecure_string3 = "System.exit(1);"

        self.assertTrue(cwe382_obj.scan(insecure_string1))
        self.assertTrue(cwe382_obj.scan(insecure_string2))
        self.assertTrue(cwe382_obj.scan(insecure_string3))

    def test_cwe395_scan(self):
        cwe395_obj = getattr(cwe_vulnerabilities, "CWE395")

        insecure_string1 = "catch (NullPointerException n) {"
        insecure_string2 = "catch (NullPointerException e) {"
        self.assertTrue(cwe395_obj.scan(insecure_string1))
        self.assertTrue(cwe395_obj.scan(insecure_string2))

    def test_cwe396_scan(self):
        cwe396_obj = getattr(cwe_vulnerabilities, "CWE396")

        insecure_string1 = "catch (Exception e) {"
        insecure_string2 = "catch (Exception exception) {"
        self.assertTrue(cwe396_obj.scan(insecure_string1))
        self.assertTrue(cwe396_obj.scan(insecure_string2))

    def test_cwe397_scan(self):
        cwe397_obj = getattr(cwe_vulnerabilities, "CWE397")

        secure_string = "public void DoSomething() throws SQLException {"
        insecure_string = "public void DoSomething() throws Exception {"

        self.assertFalse(cwe397_obj.scan(secure_string))
        self.assertTrue(cwe397_obj.scan(insecure_string))

    def test_cwe481_scan(self):
        cwe481_obj = getattr(cwe_vulnerabilities, "CWE481")

        secure_string1 = "if (value==100) {"
        secure_string2 = "if (value==true) {"
        insecure_string1 = "if (value=false) {"
        insecure_string2 = "if (value=50) {"

        self.assertFalse(cwe481_obj.scan(secure_string1))
        self.assertFalse(cwe481_obj.scan(secure_string2))
        self.assertTrue(cwe481_obj.scan(insecure_string1))
        self.assertTrue(cwe481_obj.scan(insecure_string2))

    def test_cwe491_scan(self):
        cwe491_obj = getattr(cwe_vulnerabilities, "CWE491")

        secure_string = "public final Object clone() throws CloneNotSupportedException {"
        insecure_string = "public Object clone() throws CloneNotSupportedException {"

        self.assertFalse(cwe491_obj.scan(secure_string))
        self.assertTrue(cwe491_obj.scan(insecure_string))

    def test_cwe493_scan(self):
        cwe493_obj = getattr(cwe_vulnerabilities, "CWE493")

        secure_string1 = "public final float price = 999.0;"
        secure_string2 = "public final String path = calculatePath();"
        insecure_string1 = "public float price = 111.0;"
        insecure_string2 = "public BigDecimal balance = 999999.25;"

        self.assertFalse(cwe493_obj.scan(secure_string1))
        self.assertFalse(cwe493_obj.scan(secure_string2))
        self.assertTrue(cwe493_obj.scan(insecure_string1))
        self.assertTrue(cwe493_obj.scan(insecure_string2))

    def test_cwe500_scan(self):
        cwe500_obj = getattr(cwe_vulnerabilities, "CWE500")

        secure_string1 = "public static final int PEOPLE = 2;"
        secure_string2 = "public static final String PATH = 'User/Jonah..';"
        insecure_string1 = "public static String NAME = 'Jonah';"
        insecure_string2 = "public static double PI = 3.142;"

        self.assertFalse(cwe500_obj.scan(secure_string1))
        self.assertFalse(cwe500_obj.scan(secure_string2))
        self.assertTrue(cwe500_obj.scan(insecure_string1))
        self.assertTrue(cwe500_obj.scan(insecure_string2))

    def test_cwe572_scan(self):
        cwe572_obj = getattr(cwe_vulnerabilities, "CWE572")

        secure_string1 = "thr.start();"
        secure_string2 = "thr.start();"
        insecure_string1 = "thr.run();"
        insecure_string2 = "thr.run();"

        self.assertFalse(cwe572_obj.scan(secure_string1))
        self.assertFalse(cwe572_obj.scan(secure_string2))
        self.assertTrue(cwe572_obj.scan(insecure_string1))
        self.assertTrue(cwe572_obj.scan(insecure_string2))

    def test_cwe582_scan(self):
        cwe582_obj = getattr(cwe_vulnerabilities, "CWE582")

        secure_string1 = "private final static String[] names;"
        secure_string2 = "private final static Cars[] cars;"
        insecure_string1 = "public final static double[] prices;"
        insecure_string2 = "public final static String[] countries;"

        self.assertFalse(cwe582_obj.scan(secure_string1))
        self.assertFalse(cwe582_obj.scan(secure_string2))
        self.assertTrue(cwe582_obj.scan(insecure_string1))
        self.assertTrue(cwe582_obj.scan(insecure_string2))

    def test_cwe583_scan(self):
        cwe583_obj = getattr(cwe_vulnerabilities, "CWE583")

        secure_string = "protected void finalize() {"
        insecure_string1 = "public void finalize() {"
        insecure_string2 = "public void finalize() {"

        self.assertFalse(cwe583_obj.scan(secure_string))
        self.assertTrue(cwe583_obj.scan(insecure_string1))
        self.assertTrue(cwe583_obj.scan(insecure_string2))

    def test_cwe585_scan(self):
        cwe585_obj = getattr(cwe_vulnerabilities, "CWE585")

        secure_string = "synchronized(this) { WriteToObject(); }"
        insecure_string = "synchronized(this) { }"

        self.assertFalse(cwe585_obj.scan(secure_string))
        self.assertTrue(cwe585_obj.scan(insecure_string))

    def test_cwe586_scan(self):
        cwe586_obj = getattr(cwe_vulnerabilities, "CWE586")

        secure_string = "this.finalize();"
        insecure_string = "ui.finalize();"

        self.assertFalse(cwe586_obj.scan(secure_string))
        self.assertTrue(cwe586_obj.scan(insecure_string))

    def test_cwe595_scan(self):
        cwe595_obj = getattr(cwe_vulnerabilities, "CWE595")

        secure_string = 'if (prompt.equals("pdf")) {'
        insecure_string = 'if (prompt == "pdf") {'

        self.assertFalse(cwe595_obj.scan(secure_string))
        self.assertTrue(cwe595_obj.scan(insecure_string))

    def test_cwe766_scan(self):
        cwe766_obj = getattr(cwe_vulnerabilities, "CWE766")

        secure_string1 = "private static final String USERNAME = 'Jonah123';"
        secure_string2 = "private static final String PASSWORD = readLine();"
        insecure_string1 = "public String username = 'Jonah123';"
        insecure_string2 = "public String password = 'readLine();'"

        self.assertFalse(cwe766_obj.scan(secure_string1))
        self.assertFalse(cwe766_obj.scan(secure_string2))
        self.assertTrue(cwe766_obj.scan(insecure_string1))
        self.assertTrue(cwe766_obj.scan(insecure_string2))

    def test_cwe798_scan(self):
        cwe798_obj = getattr(cwe_vulnerabilities, "CWE798")

        secure_string1 = "private static final String uname = readLine();"
        secure_string2 = "private static final String user = getEnvVariable();"
        insecure_string1 = "private static final String USERNAME = 'jonah';"
        insecure_string2 = "private String ID = '876345';"

        self.assertFalse(cwe798_obj.scan(secure_string1))
        self.assertFalse(cwe798_obj.scan(secure_string2))
        self.assertTrue(cwe798_obj.scan(insecure_string1))
        self.assertTrue(cwe798_obj.scan(insecure_string2))
