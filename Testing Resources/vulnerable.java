public class vulnerable {

    // CWE-111: Direct Use of Unsafe JNI
    public native void echoBuffer();

    // CWE-500: Public Static Field Not Marked Final
    public static String DB_URL = "jdbc:mysql://localhost/repelsec";

    // CWE-798: Use of Hard-coded Credentials
    private static final String USERNAME = "jonah";

    // CWE-259: Use of Hard-coded Password
    // CWE-766: Critical Data Element Declared Public
    public static final String PASSWORD = "password123";

    // CWE-321: Use of Hard-coded Cryptographic Key
    public static final String KEY = "tokenABC123";

    // CWE-397: Declaration of Throws for Generic Exception
    public void DoSomething() throws Exception {
        // Do something
    }

    // CWE-481: Assigning instead of Comparing
    public void Compare(int value) {
        if (value=100) {
            System.out.println(value);
        }
    }

    // CWE-491: Public cloneable() Method Without Final ('Object Hijack')
    public Object clone() throws CloneNotSupportedException {
        cloneSomething();
    }

    // CWE-493: Critical Public Variable Without Final Modifier
    public BigDecimal price = 9375.20;

    // CWE-582: Array Declared Public, Final, and Static
    public final static PRICES[] prices;

    // CWE-583: finalize() Method Declared Public
    public void finalize() {
        finaliseCode();
    }

    // CWE-595: Comparison of Object References Instead of Object Contents
    public void CompareContents(String prompt) {
        if (prompt == "pdf") {
            System.out.println("printing to PDF");
        }
    }

    // CWE-585: Empty Synchronized Block
    public void add (int value) {
        synchronized(this) { }
   }

    public static void main(String[] args) {

        // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
        try{
            Connection con = DriverManager.getConnection(DB_URL, USER, PASS);
            String user_email = request.getParameter("email"); // "random@gmail.com"
            String user_password = request.getParameter("password"); // "'OR' 1=1"

            String query = String.format("SELECT * FROM Users where email=%s AND password=%s", user_email, user_password);
            Statement stmt = con.createStatement();
            ResultSet result = stmt.executeQuery(query);
        }
        // CWE-209: Generation of Error Message Containing Sensitive Information
        catch (SQLException e) { System.out.println(e); }

        // CWE-190: Integer Overflow or Wraparound
        int over = Integer.MAX_VALUE + 5;

        // CWE-190: Integer Underflow or Wraparound
        int under = Integer.MIN_VALUE - 5;

        // CWE-246: J2EE Bad Practices: Direct Use of Sockets
        Socket sock = null;

        // CWE-326: Inadequate Encryption Strength
        try {
          File myObj = new File("C:/Users/Jonah/Documents/GitHub/REPELSEC/repelsec/config/weak_token.txt");
          Scanner myReader = new Scanner(myObj);
          if (myReader.hasNextLine()) {
            String key = myReader.nextLine();
          }
          myReader.close();
        } catch (FileNotFoundException e) {

            // CWE-382: J2EE Bad Practices: Use of System.exit()
            System.exit(1);
        }

        // CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference
        try {
            DoSomething();
        } catch (NullPointerException n) {
            n.printStackTrace();
        }

        // CWE-396: Declaration of Catch for Generic Exception
        try {
            DoSomething();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // CWE-572: Call to Thread run() instead of start()
        Thread thr = new Thread() {
        thr.run();

        // CWE-586: Explicit Call to Finalize()
        ui.finalize();

    }
}