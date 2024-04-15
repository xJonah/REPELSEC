# REPELSEC

## About the tool

A command-line tool allowing developers to find security vulnerabilities within a Java project. This is done through:

- A series of static analysis (SAST) tests that can be run against any first party code (.java, .jsp) to identify
  potential CWE vulnerabilities.
- Software composition analysis (SCA) that identifies any outdated dependencies within the pom.xml file and their
  associated
  CVE vulnerabilities.

## Installation

If your system has Python installed, open your preferred terminal or IDE and enter the following command.

`python -m pip install repelsec`

`pip install repelsec`

To keep this tool up to date, run the following command on a scheduled basis.

`pip install repelsec --upgrade`

PyPi Package - https://pypi.org/project/repelsec

## Usage

Open a terminal within your IDE and enter the following command.

`repelsec [parameters] path/filename`

Available parameters include:

- `-c / --csv` - Export results to a CSV file
- `-p / --pdf` - Export results to a PDF Report
- `-t / --txt` - Export results to a TXT file
- `-b / --blank` - Hide results from printing to the terminal. Prevents shouldersurfing.
- `-e / --password <password>` - PDF Reports can be encrypted/password-protected with this option.
- `-o / --output_path <path>` - Specify path to output results to.

This information can also be viewed locally using the following command.

`repelsec --help`

## Examples

`repelsec -c vulnerable.java`

`repelsec -p -e StrongPassword123?! -o ~/Documents/Results pom.xml`

## CWE Tests

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-111: Direct Use of Unsafe JNI
- CWE-190: Integer Overflow or Wraparound
- CWE-191: Integer Underflow (Wrap or Wraparound)
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-246: J2EE Bad Practices: Direct Use of Sockets
- CWE-259: Use of Hard-coded Password
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-326: Inadequate Encryption Strength
- CWE-382: J2EE Bad Practices: Use of System.exit()
- CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference
- CWE-396: Declaration of Catch for Generic Exception
- CWE-397: Declaration of Throws for Generic Exception
- CWE-481: Assigning instead of Comparing
- CWE-491: Public cloneable() Method Without Final ('Object Hijack')
- CWE-493: Critical Public Variable Without Final Modifier
- CWE-500: Public Static Field Not Marked Final
- CWE-572: Call to Thread run() instead of start()
- CWE-582: Array Declared Public, Final, and Static
- CWE-583: finalize() Method Declared Public
- CWE-585: Empty Synchronized Block
- CWE-586: Explicit Call to Finalize()
- CWE-595: Comparison of Object References Instead of Object Contents
- CWE-766: Critical Data Element Declared Public
- CWE-798: Use of Hard-coded Credentials