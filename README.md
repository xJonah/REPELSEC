# REPELSEC

## About the tool

A command-line tool allowing developers to find security vulnerabilities within a Java project. This is done through:

- A series of static analysis (SAST) tests that can be run against any first party code (.java, .jsp) to identify
  potential CWE vulnerabilities.
- Software composition analysis (SCA) that identifies any outdated dependencies within the pom.xml file and their
  associated
  CVE vulnerabilities.

## Installation

If your system has Python installed, open your preferred terminal and enter the following command.

`pip install repelsec`

PyPi Package - https://pypi.org/project/repelsec

## Usage

Open a terminal within your IDE and enter the following command.

`repelsec [parameters] path/filename`

Available parameters and their usage can be seen by entering the following command in the terminal.

`repelsec --help`

## Example

`repelsec -p -e StrongPassword123?! -o ~/Documents/Results pom.xml`
