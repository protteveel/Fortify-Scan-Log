# Fortify-Scan-Log
This application scans Fortify SCA log files and provides both a summary and a detailed report.

# Introduction

This document describes how to analyze the Prevoty Results log file, using the tool ScanLog.jar.

# Preparations

1. Get a copy of the tool ScanLog.jar from the Prevoty Customer Success Portal here
2. Copy ScanLog.jar onto the server running Prevoty
3. Get a copy of the Prevoty JVM arguments from the same server
4. Get the value for -Dprevoty\_log\_config. E.g.:
/opt/Apache/Tomcat-8.5.5/Prevoty/prevoty\_logging.json
5. Open the aforementioned file with your favorite text editor
6. Get the value for default\_log\_directory. E.g.:
/opt/Apache/Tomcat-8.5.5/
7. For the appender ResultJSON get the value for file\_path. E.g.:
prevoty\_json.log
8. Combine the value for default\_log\_directory and file\_path from the previous steps. E.g.:
/opt/Apache/Tomcat-8.5.5/prevoty\_json.log
9. This is &quot;_the path_&quot; to the Prevoty Results log file we will use throughout the rest of the document

# Parameters

ScanLog.jar support the following command line arguments:

- -s (for summary)
  - Provides a summary of all security, statistics, and dependency events in the Prevoty Results log file.
- -a (for analyze)
  - Provides a detailed analysis of the Prevoty Results log file
- -o (for optimize)
  - Provides the possible whitelists for Path Traversal (PT), Command Injection (CMDi), Cross-site Request Forgery (CSRF), Cross-site Scripting (XSS), etc.
- -t (for text)
  - Converts the Prevoty Results log file to text format
- -h (for HTML)
  - Converts the Prevoty Results log file to HTML format
- -q (for SQL)
  - Converts the Prevoty Results log file to a MySQL script, which can be used to load a MySQL database with the Prevoty results for further investigation

# Execution

1. Log on to the server running Prevoty
2. Open a terminal
3. Go into the directory where you have copied ScanLog.jar
  1. g.:
cd /tmp
4. Execute ScanLog.jar with _the path_ and one of the aforementioned parameters. E.g.:
  1. To get a summary:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -s
  2. To get the analysis:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -a
  3. To get the optimization:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -o
  4. To convert it to text format:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -t
  5. To convert it to HTML format:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -h
  6. To generate the MySQL script:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -q
5. Executing ScanLog.jar without any parameters will show you the help screen. E.g.:

╔══════════════════════════════════════════════════════

║ ScanLog, Scan Prevoty Results Log file.

║ Version: 3.1.1 - Sat Sep 29, 2018 - PWR Created

║ Usage: java -jar ScanLog.jar \&lt;Prevoty Results Log file path\&gt; \&lt;action\&gt;

║ Example: java -jar ScanLog.jar /opt/Prevoty/prevoty\_json.log -s

║ Action: -s Summary (default)

║ -a Analyze

║ -h Convert to HTML format output

║ -t Convert to text format output

║ -q Convert to SQL format output

║ -o Optimize for Prevoty Application Configuration file

║ Notes: - It is expected the Prevoty Results Log file is readable.

║ - Written by PWR on his own accord; Prevoty cannot be held liable for any errors, mistakes, omissions, etc.

║ - USE AT YOUR OWN RISK!

╚══════════════════════════════════════════════════════

1. jar sends it output to screen, to send it to a text file, you can redirect the output with the greater than sign (\&gt;). E.g.:
  1. To get a summary:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -s \&gt; ./prevoty\_json-summary.txt
  2. To get the analysis:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -a \&gt; ./prevoty\_json-analysis.txt
  3. To get the optimization:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -o \&gt; ./prevoty\_json-optimize.txt
  4. To convert it to text format:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -t \&gt; ./prevoty\_json.txt
  5. To convert it to HTML format:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -h \&gt; ./prevoty\_json.html
  6. To generate the MySQL script:
java -jar ./ScanLog.jar /opt/Apache/Tomcat-8.5.5/logs/prevoty\_json.log -s \&gt; ./prevoty\_json.sql

RackMultipart20210423-4-1q2pt1h.docx October 3, 2018 Page 4 of 4
