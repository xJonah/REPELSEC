# REPELSEC

## About the tool

A command-line tool allowing developers to find security vulnerabilities within a Java project.

Software composition analysis (SCA) identifies any outdated dependencies within the pom.xml file and their associated
CVE vulnerabilities.

A variety of static analysis (SAST) tests can be run to identify CWE vulnerabilities within first-party code and
remediation advice.

## Installation

If your system has Python and PIP installed, open your preferred terminal and enter the following command.

`pip install repelsec`

## Usage

Open a terminal within your IDE and enter the following command.

`repelsec [parameters] path/filename`

Available parameters and a simple description can be found by entering the following command in the terminal.

`repelsec --help`

## Examples

`repelsec -p -e StrongPassword123?! -o ~/Documents/Results pom.xml`