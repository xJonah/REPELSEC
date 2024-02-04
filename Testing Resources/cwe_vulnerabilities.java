public class cwe_vulnerabilities {

    // Hard-coded credentials (CWE-798) & hard-coded password (CWE-259)
    static final String DB_URL = "jdbc:mysql://localhost/repelsec";
    static final String USERNAME = "jonah";
    static final String PASSWORD = "password123";

    // Hard-coded cryptography key (CWE-321)
    static final String KEY = "tokenABC123";

    // native JNI Call (CWE-111) - Echo a buffer from C/C++ programming languages. Potential for buffer overflow.
    public native void echoBuffer();

    public static void main(String[] args) {

        // SQL Injection (CWE-89)
        try{
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            String user_email = request.getParameter("email"); // "random@gmail.com"
            String user_password = request.getParameter("password"); // "'OR' 1=1"

            Statement stmt = conn.createStatement();
            String query = String.format("SELECT * FROM Users where email=%s AND password=%s", user_email, user_password);
            ResultSet result = stmt.executeQuery(query);
        }
        // CWE-209: Generation of Error Message Containing Sensitive Information
        catch (SQLException e) { System.out.println(e) }

        // Inadequate encryption strength (CWE-326)
        try {
          File myObj = new File("C:/Users/Jonah/Documents/GitHub/REPELSEC/repelsec/config/weak_token.txt");
          Scanner myReader = new Scanner(myObj);
          if (myReader.hasNextLine()) {
            String key = myReader.nextLine();
          }
          myReader.close();
        } catch (FileNotFoundException e) {
          System.out.println("An error occurred.");
          e.printStackTrace();
        }

        // Empty Synchronized Block (CWE-585)
        synchronized(this) { }

        // Integer overflow (CWE-190) & integer underflow (CWE-191)
        int over = 2147483647 + 5;
        int under = Integer.MIN_VALUE - 5;

        // J2EE Bad Practices: Direct Use of Sockets (CWE-246)
        Socket sock = null;

        // J2EE Bad Practices: Use of System.exit() (CWE-382)
        if (somethingHappens) {
            System.exit(-1);
        }


    }
}