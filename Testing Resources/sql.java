import java.sql.*;
import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

public class sql {
    public static void main(String[] args) {

        // CWE-500: Public Static Field Not Marked Final
        public static String DB_URL = "jdbc:mysql://localhost/repelsec";

        // CWE-798: Use of Hard-coded Credentials
        private static final String USERNAME = "jonah";

        // CWE-259: Use of Hard-coded Password
        // CWE-766: Critical Data Element Declared Public
        public static final String PASSWORD = "password123";

        try{

            Connection con = DriverManager.getConnection(DB_URL, USERNAME, PASSWORD);

            // Example scenario: Register Process.
            // XSS Threat - <script>alert("Your system has a virus. Call 07824 123123 for support.")</script>
            String user_email = request.getParameter("email");

            // Example scenario: Login process.
            // SQL Injection Threat - 'OR' 1=1
            String user_password = request.getParameter("password");

            // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
            // XSS
            String query = String.format("SELECT * FROM Users where email=%s AND password=%s", user_email, user_password);
            Statement stmt = con.createStatement();
            ResultSet result = stmt.executeQuery(query);

            // Stored XSS
            while (result.next()) {
                System.out.println("Registered Emails: " + escapeHtml(result.getInt("email"));
            }

        }
        // CWE-209: Generation of Error Message Containing Sensitive Information
        catch (SQLException e) { System.out.println(e); }

    }
}