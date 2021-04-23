#!/bin/bash
clear
pushd /Users/percy.rotteveel/Documents/workspace/ScanLog
DIR="/Users/percy.rotteveel/Downloads/tmp"
NAME="prevoty_json.log"
java -jar ./ScanLog.jar "$DIR/$NAME" -a > "$DIR/prevoty_json_Analyze.txt"
popd