#!/bin/bash
clear
cd /Users/prevoty/Documents/workspace/ScanLog
rm -f ./ScanLog.jar
jar cfm ./ScanLog.jar MANIFEST.MF com org
java -jar ./ScanLog.jar /Users/prevoty/Downloads/temp/prevoty_json.log