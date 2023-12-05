import java.sql.*;

public class cwe_vulnerabilities {

    // CWE-798 & CWE-259
    static final String DB_URL = "jdbc:mysql://localhost/repelsec";
    static final String USERNAME = "jonah";
    static final String PASSWORD = "password123";

    public static void main(String[] args) {
        try{
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            String user_email = request.getParameter("email"); // "random@gmail.com"
            String user_password = request.getParameter("password"); // "'OR' 1=1"

            // CWE-89
            
            Statement stmt = conn.createStatement();
            String query = String.format("SELECT * FROM Users where email=%s AND password=%s", user_email, user_password);
            ResultSet result = stmt.executeQuery(query);


        catch (SQLException e) {
            e.printStackTrace();
        }
    }
}