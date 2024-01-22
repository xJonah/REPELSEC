import java.sql.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class cwe_vulnerabilities {

    // Hard-coded credentials (CWE-798) & hard-coded password (CWE-259)
    static final String DB_URL = "jdbc:mysql://localhost/repelsec";
    static final String USERNAME = "jonah";
    static final String PASSWORD = "password123";

    // Hard-coded cryptography key (CWE-321)
    static final String KEY = "tokenABC123";
    public static void main(String[] args) {

        // SQL Injection (CWE-89)
        try{
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            String user_email = request.getParameter("email"); // "random@gmail.com"
            String user_password = request.getParameter("password"); // "'OR' 1=1"

            Statement stmt = conn.createStatement();
            String query = String.format("SELECT * FROM Users where email=%s AND password=%s", user_email, user_password);
            ResultSet result = stmt.executeQuery(query);

        catch (SQLException e) {
            e.printStackTrace();
        }

        // Inadequate encryption strength (CWE-326)
        try {
          File myObj = new File("C:/Users/Jonah/Documents/GitHub/REPELSEC/repelsec/config/weak_token.txt");
          Scanner myReader = new Scanner(myObj);
          if (myReader.hasNextLine()) {
            String data = myReader.nextLine();
            System.out.println(data);
          }
          myReader.close();
        } catch (FileNotFoundException e) {
          System.out.println("An error occurred.");
          e.printStackTrace();
        }


    }
}