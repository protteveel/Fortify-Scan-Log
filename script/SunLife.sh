#!/bin/bash
clear

echo "Go into the ScanLog directory"
cd /Users/prevoty/Documents/workspace/ScanLog

echo "Remove the old files (html and txt)"
rm -f /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.html
rm -f /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.txt
rm -f /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json-optimize.txt
rm -f /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json-analyze.txt
rm -f /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json-summary.txt

echo "Convert the Prevoty Results log into HTML format (prevoty_json.html)"
java -jar ./ScanLog.jar /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.log -h>/Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.html

echo "Convert the Prevoty Results log into text format (prevoty_json.txt)"
java -jar ./ScanLog.jar /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.log -t>/Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.txt

echo "Look for optimizations in the Prevoty Results log (prevoty_json-optimize.txt)"
java -jar ./ScanLog.jar /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.log -o>/Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json-optimize.txt

echo "Do an analysis of the Prevoty Results log (prevoty_json-analyze.txt)"
java -jar ./ScanLog.jar /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.log -a>/Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json-analyze.txt

echo "Get a summary of the Prevoty Results log (prevoty_json-summary.txt)"
java -jar ./ScanLog.jar /Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json.log -s>/Users/prevoty/Documents/Prevoty/Customers/SunLife/Projects/NEXUS-Admin/Issues/999/prevoty_json-summary.txt

echo "Done!"