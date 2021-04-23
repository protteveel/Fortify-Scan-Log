package com.prevoty.cs;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.json.simple.JSONArray;
import java.net.URLDecoder;

public class ScanLog {
    
	// Prevoty MySQL database
	private static final String PREVOTY_DB = "prevoty_db";

	// Prevoty MySQL user
	private static final String PREVOTY_USR = "prevoty_usr";

	// Prevoty MySQL password
	private static final String PREVOTY_PWD = "prevoty_pwd";

	// Prevoty MySQL event table
	private static final String PREVOTY_EVENT_TABLE = "prevoty_event";
	
	// Prevoty date format
	private static final String PREVOTY_DATE_FORMAT = "%b %e %Y %H:%i:%S UTC";
	
    // The path to the Prevoty Results Log File
    String prLogFilePath = "";
    
	/** convenient "-flag opt" combination */
	private class SqlDef {
	     String sqlType;
	     boolean isString;
	     boolean isIndex;
	     public SqlDef(String sqlType, boolean isString, boolean isIndex) { this.sqlType = sqlType; this.isString = isString; this.isIndex = isIndex; }
	     public String sqlType()   { return sqlType; }
	     public boolean isString() { return isString; }
	     public boolean isIndex()  { return isIndex; }
	     public boolean isDate()   { return sqlType.equalsIgnoreCase("date"); }
	}

	// Map of Prevoty event field definition
	Map<String, SqlDef> fieldDef= new HashMap<String, SqlDef>();	 
	    
    // Map of Prevoty event fields
	Map<String, Integer> fieldMap = new HashMap<String, Integer>();
	
	// Map of categories
	Map<String, Integer> catMap = new HashMap<String, Integer>();

	// Map of PT issues
	Map<String, Integer> pathTraversalMap = new HashMap<String, Integer>();

	// Map of CMDi issues
	Map<String, Integer> commandInjectionMap = new HashMap<String, Integer>();

	// Map of Content Injection issues
	Map<String, Integer> contentInjectionMap = new HashMap<String, Integer>();

	// Map of CSRF issues
	Map<String, Integer> csrfMap = new HashMap<String, Integer>();

	// Map of XSS issues
	Map<String, Integer> xssMap = new HashMap<String, Integer>();

	// Map of unvalidated redirect issues
	Map<String, Integer> unvalRedirectMap = new HashMap<String, Integer>();

	// Map of Database Access Violation
	Map<String, Integer> databaseAccessViolationMap = new HashMap<String, Integer>();

	// Map of Dependencies
	Map<String, Integer> dependencyMap = new HashMap<String, Integer>();

	// Map of HTML Injections
	Map<String, Integer> htmlInjectionMap = new HashMap<String, Integer>();
	
	// Map of HTTP Response Splittings
	Map<String, Integer> httpResponseSplittingMap = new HashMap<String, Integer>();
	
	// Map of Unprocessed Queries
	Map<String, Integer> unprocessedQueryMap = new HashMap<String, Integer>();
	
	// Map of JSON Injections
	Map<String, Integer> jsonInjectionMap = new HashMap<String, Integer>();
	
	// Map of XML External Entities
	Map<String, Integer> xmlExternalEntityMap = new HashMap<String, Integer>();
	
	// Map of Normal
	Map<String, Integer> normalMap = new HashMap<String, Integer>();

	// Map of Request Size
	Map<String, Integer> requestSizeMap = new HashMap<String, Integer>();

	// Map of Statistics
	Map<String, Integer> statisticsMap = new HashMap<String, Integer>();
	
	// Map of SQLi issues
	Map<String, Integer> sqlInjectionMap = new HashMap<String, Integer>();
	
	// Map of Uncaught Exception
	Map<String, Integer> uncaughtExceptionMap = new HashMap<String, Integer>();
	
	// Map of Configurations
	Map<String, Integer> configurationMap = new HashMap<String, Integer>();
	
	// Map of Large Request
	Map<String, Integer> largeRequestMap = new HashMap<String, Integer>();
	
	// Map of Weak Caching
	Map<String, Integer> weakCachingMap = new HashMap<String, Integer>();
	
	// Map of Network Activity
	Map<String, Integer> networkActivityMap = new HashMap<String, Integer>();
	
	// Map of Weak Browser Cache Management
	Map<String, Integer> weakBrowserCacheManagementMap = new HashMap<String, Integer>();
	
	// Map of Weak Cryptography
	Map<String, Integer> weakCryptographyMap = new HashMap<String, Integer>();
	
	// List of categories
    public enum Category {
        Command_Injection,
        Configuration,                 // New 3.3.0
        Content_Injection,
        Cross_Site_Request_Forgery,
        Cross_Site_Scripting,
        Database_Access_Violation,
        Dependency,
        HTML_Injection,
        HTTP_Response_Splitting,       // Added to version 3.6.0 <==
        JSON_Injection,
        Large_Request,                 // New 3.3.0
        Network_Activity,              // New 3.10.0
        Normal,
        Path_Traversal,
        Request_Response,
        Request_Size,                  // Added to version 3.6.0 <==
        Statistics,
        SQL_Injection,                 // Added to version 3.6.0
        Uncaught_Exception,
        Undefined,
        Unprocessed_Query,
        Unvalidated_Redirect,
        Weak_Browser_Cache_Management, // Added to version 3.6.0 <==
        Weak_Caching,                  // New 3.3.0
        Weak_Cryptography,             // New 3.10.0
        XML_External_Entity
    }
    
	// Mapping between a string and the category
    Map<String, Category> categoryMap = new HashMap<String, Category>();

    // List of actions
    public enum Action {
    	Analyze,      // Print the summary and all data 
    	Html_Ouput,   // Print the data in HTML format
    	Optimization, // Print the configuration optimization
    	Summary,      // Print the summary
    	Text_Output,  // Print the data in HTML format
    	Sql_Output,   // Print the data in SQL format
    	Undefined     // Undefined action specified
    }
    
    // The action to execute; default is the summary
    Action theAction = Action.Summary;
    
    // List of engines
    public enum Engine {
    	Command,
    	Content,
    	Cryptography,
    	Http,
    	Network,
    	Path,
    	Query,
    	Token,
    	Undefined
    }

	// Mapping between a string and an engine
	Map<String, Engine> engineMap = new HashMap<String, Engine>();
	
    // Display how to use the program
    void displayHelp(String msg) {
    	System.out.println("╔════════════════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║ ScanLog, Scan Prevoty Results Log file.                                                ║");
        System.out.println("║ Version: 3.6.0 - Wed Nov 16, 2019                                                      ║");
        System.out.println("║ Usage:   java -jar ScanLog.jar <Prevoty results log file path> <action>                ║");
        System.out.println("║ Example: java -jar ScanLog.jar /opt/Prevoty/prevoty_json.log -s                        ║");
        System.out.println("║ Action:  -s Summary (default)                                                          ║");
        System.out.println("║          -a Analyze                                                                    ║");
        System.out.println("║          -h Convert to HTML format output                                              ║");
        System.out.println("║          -t Convert to text format output                                              ║");
        System.out.println("║          -q Convert to SQL  format output                                              ║");
        System.out.println("║          -o Optimize for Prevoty Application Configuration file                        ║");
        System.out.println("║ Notes:   - It is expected the Prevoty results log file (prevoty_json.log) is readable. ║");
        System.out.println("║          - Written by Percy Rotteveel on his own accord.                               ║");
        System.out.println("║          - Imperva cannot be held liable for any errors, mistakes, omissions, etc.     ║");
        System.out.println("║          - USE AT YOUR OWN RISK!                                                       ║");
    	System.out.println("╚════════════════════════════════════════════════════════════════════════════════════════╝");
        if (( msg != null ) && ( msg.length() > 0 )) {
            System.out.println( "\nERROR: " + msg ); 
        }
    }
    
    // Create the definition of the Prevoty event fields
    void fillSqlDef() {
    	fieldDef.put("CI_requests",           new SqlDef("INTEGER",      false, false));
    	fieldDef.put("PT_requests",           new SqlDef("INTEGER",      false, false));
    	fieldDef.put("access_type",           new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("action",                new SqlDef("VARCHAR(10)",  true,  true ));
    	fieldDef.put("app",                   new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("app_lang",              new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("app_version",           new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("category",              new SqlDef("VARCHAR(30)",  true,  true ));
    	fieldDef.put("content_requests",      new SqlDef("INTEGER",      false, false));
    	fieldDef.put("cookies",               new SqlDef("TEXT",         true,  false));
    	fieldDef.put("db_vendor",             new SqlDef("VARCHAR(20)",  true,  false));
    	fieldDef.put("dest_host",             new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("dest_ip",               new SqlDef("VARCHAR(25)",  true,  false));
    	fieldDef.put("dest_port",             new SqlDef("VARCHAR(25)",  true,  false));
    	fieldDef.put("direction",             new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("engine",                new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("forwarded_for",         new SqlDef("VARCHAR(25)",  true,  false));
    	fieldDef.put("http_content_type",     new SqlDef("VARCHAR(200)", true,  false));
    	fieldDef.put("http_method",           new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("http_referrer",         new SqlDef("TEXT",         true,  false));
    	fieldDef.put("http_user_agent",       new SqlDef("VARCHAR(200)", true,  false));
    	fieldDef.put("input",                 new SqlDef("TEXT",         true,  false));
    	fieldDef.put("invalid_attributes",    new SqlDef("INTEGER",      false, false));
    	fieldDef.put("invalid_protocols",     new SqlDef("INTEGER",      false, false));
    	fieldDef.put("invalid_tags",          new SqlDef("INTEGER",      false, false));
    	fieldDef.put("javascript_attributes", new SqlDef("INTEGER",      false, false));
    	fieldDef.put("javascript_protocols",  new SqlDef("INTEGER",      false, false));
    	fieldDef.put("javascript_tags",       new SqlDef("INTEGER",      false, false));
    	fieldDef.put("line_number",           new SqlDef("INTEGER",      false, false));
    	fieldDef.put("mode",                  new SqlDef("VARCHAR(10)",  true,  true ));
    	fieldDef.put("name",                  new SqlDef("VARCHAR(150)", true,  true ));
    	fieldDef.put("os",                    new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("os_version",            new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("output",                new SqlDef("TEXT",         true,  false));
    	fieldDef.put("path",                  new SqlDef("VARCHAR(300)", true,  false));
    	fieldDef.put("payload_type",          new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("processed",             new SqlDef("VARCHAR(10)",  true,  true ));
    	fieldDef.put("product",               new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("product_version",       new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("query",                 new SqlDef("VARCHAR(300)", true,  true ));
    	fieldDef.put("query_requests",        new SqlDef("INTEGER",      false, false));
    	fieldDef.put("result_block",          new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("result_compliant",      new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("script_name",           new SqlDef("VARCHAR(200)", true,  false));
    	fieldDef.put("session_attributes",    new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("session_creation_time", new SqlDef("DATE",         true,  false));
    	fieldDef.put("session_is_new",        new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("severity",              new SqlDef("VARCHAR(15)",  true,  true ));
    	fieldDef.put("skip",                  new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("src_ip",                new SqlDef("VARCHAR(25)",  true,  false));
    	fieldDef.put("src_port",              new SqlDef("INTEGER",      false, false));
    	fieldDef.put("stack_trace",           new SqlDef("TEXT",         true,  false));
    	fieldDef.put("statements",            new SqlDef("TEXT",         true,  false));
    	fieldDef.put("tags_balanced",         new SqlDef("INTEGER",      false, false));
    	fieldDef.put("time_span",             new SqlDef("INTEGER",      false, false));
    	fieldDef.put("timestamp",             new SqlDef("DATE",         true,  false));
    	fieldDef.put("token_requests",        new SqlDef("INTEGER",      false, false));
    	fieldDef.put("transformations",       new SqlDef("INTEGER",      false, false));
    	fieldDef.put("transport",             new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("unique_requests",       new SqlDef("INTEGER",      false, false));
    	fieldDef.put("uri_path",              new SqlDef("VARCHAR(900)", true,  false));
    	fieldDef.put("uri_query",             new SqlDef("TEXT",         true,  false));
    	fieldDef.put("url",                   new SqlDef("TEXT",         true,  false));
    	fieldDef.put("user",                  new SqlDef("VARCHAR(50)",  true,  false));
    	fieldDef.put("valid",                 new SqlDef("VARCHAR(10)",  true,  false));
    	fieldDef.put("validation_message",    new SqlDef("VARCHAR(100)", true,  false));
    	fieldDef.put("vendor",                new SqlDef("VARCHAR(20)",  true,  false));
    	fieldDef.put("version",               new SqlDef("VARCHAR(25)",  true,  false));
    	fieldDef.put("vm_runtime_version",    new SqlDef("VARCHAR(10)",  true,  false));
    }
    
    // Convert a character to an Action
    Action charToAction( char theKey ) {
    	// Set the default action
    	Action retVal = Action.Summary;
    	// Determine what to do
    	switch(theKey) {
	    	// Analyze
	    	case 'a':
	    	case 'A':
	    		retVal = Action.Analyze;
	    		break;
	    	// HTML Output
	    	case 'h':
	    	case 'H':
	    		retVal = Action.Html_Ouput;
	    		break;
	    	// Optimize
	    	case 'o':
	    	case 'O':
	    		retVal = Action.Optimization;
    		break;
	    	// Summary
	    	case 's':
	    	case 'S':
	    		retVal = Action.Summary;
	    		break;
	    	// Text Output
	    	case 't':
	    	case 'T':
	    		retVal = Action.Text_Output;
	    		break;
	    	// SQL Output
	    	case 'q':
	    	case 'Q':
	    		retVal = Action.Sql_Output;
	    		break;
    	}
    	// Return the result
    	return retVal;
    }
    
    // Convert  string to an engine
    Engine stringToEngine( String theEngine ) {
    	// Set the default return value
    	Engine retVal = Engine.Undefined;
    	// Do we have an engine
    	if (( theEngine != null ) && ( theEngine.length() > 0 )) {
        	// Convert the given value to lower case and remove all white spaces
    		theEngine = theEngine.trim().toLowerCase();
    		// Find the string in the engine map
    		retVal = engineMap.get(theEngine);
    		// Did we not find it?
    		if (retVal == null) {
    			// Set it to undefined
    			retVal = Engine.Undefined;
    			// Inform the user
    			displayHelp("Prevoty engine \"" + theEngine + "\" is not implemented.");
    		}
    	}
    	else {
    		// Inform the user
    		displayHelp("Empty string provided for Prevoty engine.");
    	}
    	// Return the result
    	return retVal;
    }
    
    // Convert  string to an category
    Category stringToCategory( String theCategory ) {
    	// Set the default return value
    	Category retVal = Category.Undefined;
    	// Do we have an category
    	if (( theCategory != null ) && ( theCategory.length() > 0 )) {
        	// Convert the given value to lower case and remove all white spaces
    		theCategory = theCategory.trim().toLowerCase();
    		// Find the string in the category map
    		retVal = categoryMap.get(theCategory);
    		// Did we not find it?
    		if (retVal == null) {
    			// Set it to undefined
    			retVal = Category.Undefined;
    			// Inform the user
    			displayHelp("Prevoty category \"" + theCategory + "\" is not implemented.");
    		}
    	}
    	else {
    		// Inform the user
    		displayHelp("Empty string provided for Prevoty category.");
    	}
    	// Return the result
    	return retVal;
    }
    
    // Constructor
    ScanLog( String[] arguments ) {
        // Do we have a file name?
        if (( arguments != null ) && ( arguments.length > 0 )){
            // Get the Prevoty results log file
        	for (int i = 0; i < arguments.length; i++ ) {
        		// Get the argument
        		String argument = arguments[i];
        		// Does it start with a '-'?
        		if( argument.startsWith("-")) {
        			// Get the action
        			if ( argument.length() > 1) {
        				theAction = charToAction( argument.toLowerCase().charAt(1));
        			}
        		}
        		else {
            		if ( prLogFilePath.length() > 0 ) {
            			prLogFilePath += " ";
            		}
            		prLogFilePath += arguments[i];
        		}
        	}
        }
    }
    
    // Extend the length of the string
    String extendStr(boolean front, String filler, int length, String line) {
    	if((filler != null) && (filler.length() > 0) && (line != null) && (line.length() > 0) && (length > line.length())) {
    		while(line.length() < length ) {
    			// Add to the front?
    			if(front) {
    				line = filler + line;
    			}
    			else {
    				line += filler;
    			}
    		}
    	}
    	// Return the result
    	return line;
    }
    
    // Add another key to the map.
    // If the key exists, increase the counter for the existing key.
    // If the key does not exists, add the key, with a counter of 1.
    void addKey(Map<String, Integer> theMap, String theKey) {
    	// Do we have a key
    	if((theKey != null) && (theKey.length() > 0)) {
    		// Get the count for the key
    		Integer keyCount = theMap.get(theKey);
    		// Is the key already in the map?
    		if( keyCount != null ) {
    			// Increase the current counter by 1
    			theMap.replace(theKey, keyCount + 1);    			
    		}
    		else {
    			// Add the key
    			theMap.put(theKey, 1);
    		}
    	}	
    }
    
    // Add another category to the list of categories
    void addCategory(String category) {
    	// Add the category to the list of categories
    	addKey(catMap, category);
    }
    
    // Add another domain to the list of domains
    void addUnvalRedirect(String uriQuery) {
    	// Add the domain to the list of unvalidated redirects
    	addKey(unvalRedirectMap, uriQuery);
    }
    
    // Add another URI to the CSRF list
    void addCSRF(String uriPath) {
    	// Add the URI to the list of CSRF's
    	addKey(csrfMap, uriPath);
    }
    
    // Add another URI to the XSS list
    void addXSS(String uriPath) {
    	// Add the URI to the list of XSS's
    	addKey(xssMap, uriPath);
    }
    
    // Add another path to the list of PT
    void addPathTraversal(String path) {
    	// Do we have a category?
    	if((path != null) && (path.length() > 0)) {
			// Is there a file separator at the end?
			int lastFileSeparator = path.lastIndexOf(File.separator);
			// Remove everything after the last file separator
			if((lastFileSeparator != -1) && (path.length() > 1 )){
				path = path.substring(0, lastFileSeparator + 1);
			}
			// Add the path to the list of PT's
	    	addKey(pathTraversalMap, path);
    	}
    }

    // Add another JAR to the list of dependencies
    void addDependency(String path) {
    	// Add the path to the list of dependencies
    	addKey(dependencyMap, path);
    }

    // Add another command to the list of commands
    void addCommandInjection(String commandLine) {
    	// Add the command to the list of CMDi's
    	addKey(commandInjectionMap, commandLine);
    }
    
    // Add another URL to the list of content injections
    void addContentInjection(String URL) {
    	// Add the URL to the list of content injections
    	addKey(contentInjectionMap, URL);
    }
    
    // Get the list of row create violations
    String get_row_create_violations(JSONArray row_create_violations) {
    	// Set the default result
    	String retVal = "";
    	// Get the size of the array
    	int size  = row_create_violations.size();
    	// Parse through the array
    	for(int index = 0; index < size; index++ ) {
    		// Get the object
    		JSONObject row_create_violation = (JSONObject)row_create_violations.get(index);
    		// Do we have an object?
    		if(row_create_violation != null) {
    			// Is there an element in the list already?
    			if((retVal != null) && (retVal.length() > 0)){
    				// Add the divider
    				retVal += " - ";
    			} 
    			// Add the element
    			retVal += row_create_violation.toString();
    		}
    	}
    	// Return the result
    	return retVal;
    }
    
    // Get the list of function violations
    String get_function_violations(JSONArray function_violations) {
    	// Set the default result
    	String retVal = "";
    	// Get the size of the array
    	int size  = function_violations.size();
    	// Parse through the array
    	for(int index = 0; index < size; index++ ) {
    		// Get the object
    		JSONObject function_violation = (JSONObject)function_violations.get(index);
    		// Do we have an object?
    		if(function_violation != null) {
    			// Get the function name
    			String funcName = (String)function_violation.get("name");
    			// Set the default argument list
    			String argList = "";
    			// Get the arguments
    			JSONArray arguments = (JSONArray)function_violation.get("arguments");
    			// Do we have some arguments?
    			if((arguments != null) && (arguments.size() > 0)){
    				// Parse the list of arguments
    				for(int aIndex = 0 ;aIndex < arguments.size(); aIndex++) {
        				// Get the argument
        				JSONObject argument = (JSONObject)arguments.get(index);
        				// Do we have an argument?
        				if(argument != null) {
        					// Does it has a "database"?
        					String database = (String)argument.get("database");
        					if((database != null) && (database.length() > 0 )) {
        						// Is the argument list not empty?
        						if((argList != null) && (argList.length() > 0)) {
        							// Add a divider
        							argList += ", ";
        						}
        						// Add the database
        						argList += "database{" + database + "}";
        					} 
                            // Does it has a "table"?
                            String table = (String)argument.get("table");
                            if((table != null) && (table.length() > 0 )) {
                                // Is the argument list not empty?
                                if((argList != null) && (argList.length() > 0)) {
                                    // Add a divider
                                    argList += ", ";
                                }
                                // Add the table
                                argList += "table{" + table + "}";
                            } 
                            // Does it has a "column"?
                            String column = (String)argument.get("column");
                            if((column != null) && (column.length() > 0 )) {
                                // Is the argument list not empty?
                                if((argList != null) && (argList.length() > 0)) {
                                    // Add a divider
                                    argList += ", ";
                                }
                                // Add the column
                                argList += "column{" + column + "}";
                            }
        				}
    				}
    				// Create the function with the argument list
    				funcName += "(" + argList + ")";
    			} else {
    				// Create an empty argument list
    				funcName += "()";
    			}
    			// Is there an element in the list already?
    			if((retVal != null) && (retVal.length() > 0)){
    				// Add the divider
    				retVal += " - ";
    			}
    			// Add the element
    			retVal += funcName;
    		}
    	}
    	// Return the result
    	return retVal;
    }

    // Get the list of column update violations
    String get_column_update_violations(JSONArray column_update_violations) {
        // Set the default result
        String retVal = "";
        // Get the size of the array
        int size  = column_update_violations.size();
        // Parse through the array
        for(int index = 0; index < size; index++ ) {
            // Get the object
            JSONObject column_update_violation = (JSONObject)column_update_violations.get(index);
            // Do we have an object?
            if(column_update_violation != null) {
                // Is there an element in the list already?
                if((retVal != null) && (retVal.length() > 0)){
                    // Add the divider
                    retVal += " - ";
                } 
                // Add the element
                retVal += column_update_violation.toString();
            }
        }
        // Return the result
        return retVal;
    }

    // Get the list of union violations
    String get_union_violations(JSONArray union_violations) {
        // Set the default result
        String retVal = "";
        // Get the size of the array
        int size  = union_violations.size();
        // Parse through the array
        for(int index = 0; index < size; index++ ) {
            // Get the object
            JSONObject union_violation = (JSONObject)union_violations.get(index);
            // Do we have an object?
            if(union_violation != null) {
                // Is there an element in the list already?
                if((retVal != null) && (retVal.length() > 0)){
                    // Add the divider
                    retVal += " - ";
                } 
                // Add the element
                retVal += union_violation.toString();
            }
        }
        // Return the result
        return retVal;
    }

    // Get the list of row delete violations
    String get_row_delete_violations(JSONArray row_delete_violations) {
        // Set the default result
        String retVal = "";
        // Get the size of the array
        int size  = row_delete_violations.size();
        // Parse through the array
        for(int index = 0; index < size; index++ ) {
            // Get the object
            JSONObject row_delete_violation = (JSONObject)row_delete_violations.get(index);
            // Do we have an object?
            if(row_delete_violation != null) {
                // Is there an element in the list already?
                if((retVal != null) && (retVal.length() > 0)){
                    // Add the divider
                    retVal += " - ";
                } 
                // Add the element
                retVal += row_delete_violation.toString();
            }
        }
        // Return the result
        return retVal;
    }

    // Get the list of subquery violations
    String get_subquery_violations(JSONArray subquery_violations) {
        // Set the default result
        String retVal = "";
        // Get the size of the array
        int size  = subquery_violations.size();
        // Parse through the array
        for(int index = 0; index < size; index++ ) {
            // The list of arguments
            String argList = "";
            // Get the argument
            JSONObject argument = (JSONObject)subquery_violations.get(index);
            // Do we have an argument?
            if(argument != null) {
                // Does it has a "database"?
                String database = (String)argument.get("database");
                if((database != null) && (database.length() > 0 )) {
                    // Is the argument list not empty?
                    if((argList != null) && (argList.length() > 0)) {
                        // Add a divider
                        argList += ", ";
                    }
                    // Add the database
                    argList += "database{" + database + "}";
                } 
                // Does it has a "table"?
                String table = (String)argument.get("table");
                if((table != null) && (table.length() > 0 )) {
                    // Is the argument list not empty?
                    if((argList != null) && (argList.length() > 0)) {
                        // Add a divider
                        argList += ", ";
                    }
                    // Add the table
                    argList += "table{" + table + "}";
                } 
                // Does it has a "column"?
                String column = (String)argument.get("column");
                if((column != null) && (column.length() > 0 )) {
                    // Is the argument list not empty?
                    if((argList != null) && (argList.length() > 0)) {
                        // Add a divider
                        argList += ", ";
                    }
                    // Add the column
                    argList += "column{" + column + "}";
                }
                // Is there a list of arguments in the list already?
                if((retVal != null) && (retVal.length() > 0)){
                    // Add the divider
                    retVal += ", ";
                }
                // Add the list of arguments
                retVal += "(" + argList + ")";
            }
        }
        // Return the result
        return retVal;
    }

    // Get the list of column read violations
    String get_column_read_violations(JSONArray column_read_violations) {
        // Set the default result
        String retVal = "";
        // Get the size of the array
        int size  = column_read_violations.size();
        // Parse through the array
        for(int index = 0; index < size; index++ ) {
            // The list of arguments
            String argList = "";
            // Get the argument
            JSONObject argument = (JSONObject)column_read_violations.get(index);
            // Do we have an argument?
            if(argument != null) {
                // Does it has a "database"?
                String database = (String)argument.get("database");
                if((database != null) && (database.length() > 0 )) {
                    // Is the argument list not empty?
                    if((argList != null) && (argList.length() > 0)) {
                        // Add a divider
                        argList += ", ";
                    }
                    // Add the database
                    argList += "database{" + database + "}";
                } 
                // Does it has a "table"?
                String table = (String)argument.get("table");
                if((table != null) && (table.length() > 0 )) {
                    // Is the argument list not empty?
                    if((argList != null) && (argList.length() > 0)) {
                        // Add a divider
                        argList += ", ";
                    }
                    // Add the table
                    argList += "table{" + table + "}";
                } 
                // Does it has a "column"?
                String column = (String)argument.get("column");
                if((column != null) && (column.length() > 0 )) {
                    // Is the argument list not empty?
                    if((argList != null) && (argList.length() > 0)) {
                        // Add a divider
                        argList += ", ";
                    }
                    // Add the column
                    argList += "column{" + column + "}";
                }
                // Is there a list of arguments in the list already?
                if((retVal != null) && (retVal.length() > 0)){
                    // Add the divider
                    retVal += ", ";
                }
                // Add the list of arguments
                retVal += "(" + argList + ")";
            }
        }
        // Return the result
        return retVal;
    }

    // Get the list of join violations
    String get_join_violations(JSONArray join_violations) {
        // Set the default result
        String retVal = "";
        // Get the size of the array
        int size  = join_violations.size();
        // Parse through the array
        for(int index = 0; index < size; index++ ) {
            // Get the object
            JSONObject join_violation = (JSONObject)join_violations.get(index);
            // Do we have an object?
            if(join_violation != null) {
                // Is there an element in the list already?
                if((retVal != null) && (retVal.length() > 0)){
                    // Add the divider
                    retVal += " - ";
                } 
                // Add the element
                retVal += join_violation.toString();
            }
        }
        // Return the result
        return retVal;
    }

    // Add another statement to the list of Database Access Violations
    void addDatabaseAccessViolation(JSONArray statements ) {
    	// Do we have a statement?
    	if(statements != null) {
			// Get the statement object
			JSONObject statement = (JSONObject)statements.get(0);
			// Do we have a statement object?
			if(statement != null) {
				// Get the violations object
    			JSONObject violations = (JSONObject)statement.get("violations");
    			// Do we have a violations object?
    			if(violations != null) {
    				// Get the intelligence object
    				JSONObject intelligence = (JSONObject)statement.get("intelligence");
    				// Do we have a intelligence object?
    				if(intelligence != null) {
    			    	// Set the default result
    			    	String result = "";
    			    	
    			    	// Get the row create violations
    					String row_create_violations = get_row_create_violations((JSONArray)violations.get("row_create_violations"));
    					// Do we have row create violations?
    					if((row_create_violations != null) && (row_create_violations.length() > 0)){
    						// Add the row create violations
    						result = "[Row Create Violations: " + row_create_violations + "] ";
    					}
    					
                        // Get the function violations
                        String function_violations = get_function_violations((JSONArray)violations.get("function_violations"));
                        // Do we have function violations?
                        if((function_violations != null) && (function_violations.length() > 0 )){
                            // Add the function violations
                            result += "[Function Violations: " + function_violations + "] ";
                        }

                        // Get the column update violations
                        String column_update_violations = get_column_update_violations((JSONArray)violations.get("column_update_violations"));
                        // Do we have column update violations?
                        if((column_update_violations != null) && (column_update_violations.length() > 0)){
                            // Add the column update violations
                            result += "[ Column Update Violations: " + column_update_violations + "] ";
                        }
                        
                        // Get the union violations
                        String union_violations = get_union_violations((JSONArray)violations.get("union_violations"));
                        // Do we have union violations?
                        if((union_violations != null) && (union_violations.length() > 0)){
                            // Add the union violations
                            result += "[ Union Violations: " + union_violations + "] ";
                        }
                        
                        // Get the row delete violations
                        String row_delete_violations = get_row_delete_violations((JSONArray)violations.get("row_delete_violations"));
                        // Do we have row delete violations?
                        if((row_delete_violations != null) && (row_delete_violations.length() > 0)){
                            // Add the row delete violations
                            result += "[Row Delete Violations: " + row_delete_violations + "] ";
                        }
                        
                        // Get the subquery violations
                        String subquery_violations = get_subquery_violations((JSONArray)violations.get("subquery_violations"));
                        // Do we have subquery violations?
                        if((subquery_violations != null) && (subquery_violations.length() > 0 )){
                            // Add the subquery violations
                            result += "[Subquery Violations: " + subquery_violations + "] ";
                        }

                        // Get the column read violations
                        String column_read_violations = get_column_read_violations((JSONArray)violations.get("column_read_violations"));
                        // Do we have column read violations?
                        if((column_read_violations != null) && (column_read_violations.length() > 0 )){
                            // Add the column read violations
                            result += "[Column Read Violations: " + column_read_violations + "] ";
                        }

                        // Get the join violations
                        String join_violations = get_join_violations((JSONArray)violations.get("join_violations"));
                        // Do we have join violations?
                        if((join_violations != null) && (join_violations.length() > 0)){
                            // Add the join violations
                            result += "[Join Violations: " + join_violations + "] ";
                        }
                        
                        // Add the statement to the list of Database Access Violations
			        	addKey(databaseAccessViolationMap, result);
    				}
    			}
			}
    	}
    }
    
    
    void addHtmlInjection(String input ) {
    	// Add the input to the list of HTMLi's
    	addKey(htmlInjectionMap, input);
    }
    
    void addHttpResponseSplitting(String httpMethod, String httpReferrer) {
    	// Do we have a HTTP referrer?
    	if ((httpReferrer != null) && (httpReferrer.length() > 0)) {
        	// Add the HTTP method and the HTTP referrer to the list of HTTP response splitting
        	addKey(httpResponseSplittingMap, httpMethod + ": " + httpReferrer);
    	} else {
        	// Add the HTTP method to the list of HTTP response splitting
        	addKey(httpResponseSplittingMap, httpMethod);
    	}
    }
    
    void addNormal(String input ) {
    	// Add the  input to the list of normal's
    	addKey(normalMap, input);
    }
    
    void addUnprocessedQuery(String query) {
    	// Add the query to the list of unprocessed queries
    	addKey(unprocessedQueryMap, query);
    }
    
    void addJsonInjection(String uriQuery) {
    	// Add the URI query to the list of JSONi's
    	addKey(jsonInjectionMap, uriQuery);
    }
    
    void addXmlExternalEntity(String docTypeTag) {
    	// Add the doc type tag to the list of XML external entities
    	addKey(xmlExternalEntityMap, docTypeTag);
    }
    
    void addStatistics(String input) {
    	// Add the app to the list of Statistics
    	addKey(statisticsMap, input);
    }
    
    // Add another SQL query to the list of commands
    void addSqlInjection(String sqlQuery ) {
    	// Add the SQL query to the list of SQLi's
    	addKey(sqlInjectionMap, sqlQuery);
    }
        
    void addUncaughtException(String input) {
    	// Add the uncaught exception to the list of uncaught exceptions
    	addKey(uncaughtExceptionMap, input);
    }
    
    void addConfiguration(String timestamp) {
    	// Add the time stamp the new configuration was loaded to the list of configurations
    	addKey(configurationMap, timestamp);
    }
    
    void addLargeRequest(Long requestSize, Long maxRequestSize) {
    	// Add the request size and the max to the list of large requests
    	addKey(largeRequestMap, maxRequestSize + " / " + requestSize);
    }
    
    void addRequestSize(Long maxRequestSize, Long requestSize, Long requestSizeDifference ) {
    	// Add the max request size, request size, and the request size difference to the list of request sizes
    	addKey(requestSizeMap, maxRequestSize + " / " + requestSize + " / " + requestSizeDifference);
    }
    
    void addWeakCaching(String action) {
    	// Add the action taken against weak caching
    	addKey(weakCachingMap, action);
    }
    
    void addWeakBrowserCacheManagement(String httpUserAgent) {
    	// Add the HTTP user agent to the list of Weak Browser Cache Management list
    	addKey(weakBrowserCacheManagementMap, httpUserAgent);
    }
    
    void addWeakCryptography(String algorithm) {
    	// Add the algorithm to the list of weak cryptography
    	addKey(weakCryptographyMap, algorithm);
    }
    
    void addNetworkActivity(String outboundConnection ) {
    	// Add the outbound connection to the list of network activity
    	addKey(networkActivityMap, outboundConnection);
    }
    
    // Searches for a tag within the URI Query
    String searchForTag(String uriQuery, String searchTag) {
    	// Set the return value
    	String htmlTag = null;
    	// Do we have an URI query?
    	if((uriQuery != null) && (uriQuery.length() > 0)) {
    		// Index
    		int index = 0;
    		// URI query length
    		int uriQueryLen = uriQuery.length();
    		// Are we in an HTML tag?
    		boolean inHtmlTag = false;
    		// Loop through the URI query
    		while(index < uriQueryLen) {
    			char key = uriQuery.charAt(index);
    			// Are we in an HTML tag?
    			if(inHtmlTag) {
					// Add the character to the HTML tag
					htmlTag += key;
    				// Is the key a right angle bracket?
    				if(key == '>') {
    					// Terminate the HTML tag
    					inHtmlTag = false;
    					// Does the HTML tag contain the string we are looking for?
    					if (htmlTag.indexOf(searchTag) != -1) {
    						// Terminate the loop
    						index = uriQueryLen;
    					}
    				}
    			}
    			else {
    				// Is the key a left angle bracket?
    				if(key == '<') {
    					// Start a new HTML tag
    					htmlTag = "<";
    					// We are in an HTML tag now
    					inHtmlTag = true;
    				}    				
    			}
    			// Increase the index
    			index++;
    		}
    	}
    	// return the result
    	return htmlTag;
    }
    
    // Print the contents of a hash map
    void printSet(String theTitle, Set theSet, boolean printUnique, boolean printNumbers ) {
    	System.out.println("╔══════════════════════════════════════════════════════╗");
    	theTitle = extendStr(false, " ", 55, "║ " + theTitle + ": ") + "║";
    	System.out.println(theTitle);
    	System.out.println("╚══════════════════════════════════════════════════════╝");
    	// Track the total
    	Integer total = 0;
    	// Get an iterator
    	Iterator theIterator = theSet.iterator();
		// Set the counter
		Integer theCount = 0;
		// Set the key
		String theKey = "";
        while(theIterator.hasNext()) {
            Map.Entry me2 = (Map.Entry)theIterator.next();
            // Get the counter
		    theCount = (Integer) me2.getValue();
		    // Get the key
		    theKey = (String) me2.getKey();
		    // Print the numbers?
		    if(printNumbers) {
			    // Print the results with the numbers
			    System.out.println("  " + extendStr(true, " ", 5, theCount.toString()) + " " + theKey);
		    }
		    else {
			    // Print the results
			    System.out.println(theKey);
			    // Print separator
			    System.out.println("  ----------------------------------------");
		    }
		    // Add the total
		    total += theCount;
       }
	    // Print the numbers?
	    if(printNumbers) {
	    	System.out.println("  ───── +");
	    	if (printUnique) {
	    	    System.out.println("  " + extendStr(true, " ", 5, total.toString()) + " Total (" + theSet.size() + " unique)");
	    	}
	    	else {
	    	    System.out.println("  " + extendStr(true, " ", 5, total.toString()) + " Total");
	    	}
	    }
    }
    
    // Sort the hash map and print it
    void printSortedHashMap(String title, Map<String, Integer> hashMap, boolean printUnique, boolean printNumbers) {
    	// Do we have some entries?
    	if ((hashMap != null) && (!hashMap.isEmpty())) {
        	// Sort the hash map
        	Map<String, Integer> treeMap = new TreeMap<String, Integer>(hashMap);
            Set sortedTreeMap = treeMap.entrySet();
        	// Print the list of categories
        	printSet(title, sortedTreeMap, printUnique, printNumbers);        	
    	}
    }
    
    // Extracts the domain from an URI query
    String getDomain(String uriQuery) {
        // Get everything after "https://"
    	String protocol = "https://";
        int beginIndex = uriQuery.indexOf(protocol);
        if( beginIndex != -1 ) {
        	uriQuery = uriQuery.substring(beginIndex + protocol.length());
        }
        else
        {
            // Get everything after "http://"
        	protocol = "http://";
            beginIndex = uriQuery.indexOf(protocol);
            if( beginIndex != -1 ) {
            	uriQuery = uriQuery.substring(beginIndex + protocol.length());
            }
        }
        // Cut everything of after "/"
        int endIndex = uriQuery.lastIndexOf("/");
        if(endIndex != -1) {
        	uriQuery = uriQuery.substring(0, endIndex);
        }
    	// Return the result
    	return uriQuery;
    }
    
    // In the case where we cannot URL decode, just return the input
    String myUrlDecode(String input) {
    	// Set the return value
    	String retVal = "";
    	// Do we have an input?
    	if((input != null) && (input.length() > 0)) {
        	// Try to URL decode
        	try {
        		retVal = URLDecoder.decode(input, "UTF-8");
        	}
        	catch (IllegalArgumentException e) {
        		// Just return the input
        		retVal = input;
        	} catch (UnsupportedEncodingException e) {
    			// Just return the input
        		retVal = input;
    		}
    	}
    	// Return the result
    	return retVal;
    }
    
    // Parse and create a summary the Prevoty Results log file (JSON)
    void runSummary() {
        // Try to parse the file
        try{
            // Create the file handle
        	FileReader fileHandle = new FileReader(prLogFilePath);
        	// Create the buffer handle 
        	BufferedReader bufferHandle = new BufferedReader(fileHandle);
        	// Create a JSON parser
        	JSONParser parser = new JSONParser();
        	// Read the file line-by-line
        	for(String line; (line = bufferHandle.readLine()) != null; ) {
        		try {
            		// Create the JSON object
            		JSONObject json = (JSONObject) parser.parse(line);
            		// Get the category
            		String category = (String) json.get("category");
            		// Save the category
            		addCategory(category);
        		}
        		catch (ParseException e) {
        			// There is an error in the JSON object
        			System.out.println("Could not parse the line \"" + line + "\"");
                }        		
            }
        	// Close the buffer reader
        	bufferHandle.close();
        	// Print the list of categories
            printSortedHashMap("Categories", catMap, false, true);
        } catch (FileNotFoundException e) {
        	if (( prLogFilePath != null ) && ( prLogFilePath.length() > 0 )) {
                displayHelp("Could not find the Prevoty results log file \"" + prLogFilePath + "\"");
        	}
        	else {
                displayHelp("");
        	}
        } catch (IOException e) {
            displayHelp("Could not read the Prevoty results log file \"" + prLogFilePath + "\"");
        } 
    }
    
    // Print out the MySQL script to create and delete database and user
    void runSqlOutputPrimer() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Create the Prevoty database and user");
    	System.out.println("###########################################");
        System.out.println("# mysql -h localhost -u root mysql -p");
        System.out.println("# CREATE DATABASE `"+PREVOTY_DB+"`;");
        System.out.println("# CREATE USER '"+PREVOTY_USR+"'@'%' IDENTIFIED BY '"+PREVOTY_PWD+"';");
        System.out.println("# GRANT ALL PRIVILEGES ON `"+PREVOTY_DB+"`.* TO '"+PREVOTY_USR+"'@'%' WITH GRANT OPTION;");
        System.out.println("# FLUSH PRIVILEGES;");
        System.out.println("# EXIT");
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Delete the Prevoty database and user");
    	System.out.println("###########################################");
        System.out.println("# mysql -h localhost -u root mysql -p");
        System.out.println("# REVOKE USAGE ON *.* FROM '"+PREVOTY_USR+"'@'%';");
        System.out.println("# REVOKE ALL PRIVILEGES ON `"+PREVOTY_DB+"`.* FROM '"+PREVOTY_USR+"'@'%';");
        System.out.println("# DROP USER '"+PREVOTY_USR+"'@'%';");
        System.out.println("# DROP DATABASE `"+PREVOTY_DB+"`;");
        System.out.println("# FLUSH PRIVILEGES;");
        System.out.println("# EXIT");
    }
    
    // Print out the SQL script to run a script
    void runSqlOutputRunScript() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Run MySQL script from file");
    	System.out.println("###########################################");
    	System.out.println("# mysql -h localhost -u "+PREVOTY_USR+" "+PREVOTY_DB+" -p < ./prevoty_script.sql");
    }
    
    // Print out the SQL script to drop the table
    void runSqlOutputDropTable() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Drop the Prevoty table");
    	System.out.println("###########################################");
    	System.out.println("# mysql -h localhost -u "+PREVOTY_USR+" "+PREVOTY_DB+" -p");
    	System.out.println("DROP TABLE "+PREVOTY_EVENT_TABLE+";");
    }
    
    // Print out the SQL script to find PT whitelist
    void runSqlOutputFindPtWhitelist() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Path Traversal - Whitelisted Paths");
    	System.out.println("###########################################");
    	System.out.println("# SELECT path");
    	System.out.println("# FROM prevoty_event");
    	System.out.println("# WHERE ((category = \"Path Traversal\") AND (severity <> \"informational\"))");
    	System.out.println("# GROUP BY path;");
    }

    // Print out the SQL script to find CSRF x-origin
    void runSqlOutputFindCsrfXorigin() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Cross-Site Request Forgery - Permitted Origins");
    	System.out.println("###########################################");
    	System.out.println("# SELECT mode, action, severity, dest_host, SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(http_referrer, '/', 3), '://', -1), '/', 1), '?', 1) AS \"http_referrer (domain)\", SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(url, '/', 3), '://', -1), '/', 1), '?', 1) AS \"url (domain)\"");
    	System.out.println("# FROM prevoty_event");
    	System.out.println("# WHERE ((category = \"Cross-Site Request Forgery\") AND (severity <> \"informational\") AND (validation_message = \"mismatched origin\"))");
    	System.out.println("# ORDER BY action, severity;");
    }
    
    // Print out the SQL script to find CSRF whitelist
    void runSqlOutputFindCsrfwhitelist() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Cross-Site Request Forgery - Generation & Validation Whitelist");
    	System.out.println("###########################################");
    	System.out.println("# SELECT uri_path");
    	System.out.println("# FROM prevoty_event ");
    	System.out.println("# WHERE ((category = \"Cross-Site Request Forgery\") AND (severity <> \"informational\") AND (validation_message = \"token is missing\") AND (http_method = \"POST\"))");
    	System.out.println("# GROUP BY uri_path;");
    }
    
    // Print out the SQL script to find XSS ignored URL Paths
    void runSqlOutputFindXssIgnoredUrlPaths() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Content Injection - Ignored URL Paths");
    	System.out.println("###########################################");
    	System.out.println("# SELECT uri_path");
    	System.out.println("# FROM prevoty_event ");
    	System.out.println("# WHERE ((category = \"Cross-Site Scripting\") AND (severity <> \"informational\")))");
    	System.out.println("# GROUP BY uri_path;");
    }
    
    // Print out the SQL script to create the table
    void runSqlOutputCreateTable() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Create the Prevoty table");
    	System.out.println("###########################################");
    	// Create the table
    	System.out.println("CREATE TABLE "+PREVOTY_EVENT_TABLE+" (");
    	// Get the list of keys
    	// Set theSet = fieldDef.keySet();
    	// Key counter
    	int keyCounter = 0;
    	// Loop through the key set
    	for (Map.Entry<String, SqlDef> entry : fieldDef.entrySet()) {
    		// Get the field name
    		String fieldName = entry.getKey();
    		// Get the SQL definition
    		SqlDef sqlDef = entry.getValue();
		    // Print the column definition
		    System.out.print("\t" + fieldName + " " + sqlDef.sqlType() );
		    // Increase the key counter
		    keyCounter++;
		    // Is this the last field?
		    if (keyCounter == fieldDef.size()) {
		    	// Close the table creation
		    	System.out.println(");");
		    }
		    else {
		    	// Print column separator
		    	System.out.println(",");
		    }
    	}
    }
    
    // Create the indexes
    void runSqlOutputCreateIndex() {
    	System.out.println();
    	System.out.println("###########################################");
    	System.out.println("# Create the Prevoty indexes");
    	System.out.println("###########################################");
    	// Loop through the key set
    	for (Map.Entry<String, SqlDef> entry : fieldDef.entrySet()) {
    		// Get the field name
    		String fieldName = entry.getKey();
    		// Get the SQL definition
    		SqlDef sqlDef = entry.getValue();
    		// DFoes this field need an index?
    		if(sqlDef.isIndex()) {
    			// Create the index
    		    System.out.println("CREATE INDEX idx_"+fieldName+" ON "+PREVOTY_EVENT_TABLE+" ("+fieldName+");");
    		}
    	}
    }
    
    // Parse and print the Prevoty Results log file (JSON) in SQL format
    void runSqlOutput() {
    	// Set up the SQL definitions
    	fillSqlDef();
    	// SQL script - Primer
    	runSqlOutputPrimer();
    	// SQL script - Run script from file
    	runSqlOutputRunScript();
    	// SQL script - Drop table 
    	runSqlOutputDropTable();
    	// SQL script - Find PT whitelist
    	runSqlOutputFindPtWhitelist();
    	// SQL script - Find CSRF x-orgin permits
    	runSqlOutputFindCsrfXorigin();
    	// SQL script - Find CSRF whitelist
    	runSqlOutputFindCsrfwhitelist();
        // SQL script - Find XSS ignored URL Paths
        runSqlOutputFindXssIgnoredUrlPaths();
    	// SQL script - Create table
    	runSqlOutputCreateTable();
    	// SQL script - Create indexes
    	runSqlOutputCreateIndex();
    	// SQL script - Fill table
        try{
        	System.out.println();
        	System.out.println("###########################################");
        	System.out.println("# Fill the Prevoty event table");
        	System.out.println("###########################################");
            // Create the file handle
        	FileReader fileHandle = new FileReader(prLogFilePath);
        	// Create the buffer handle 
        	BufferedReader bufferHandle = new BufferedReader(fileHandle);
        	// Create a JSON parser
        	JSONParser parser = new JSONParser();
        	// Line count
        	int lineCount = 0;
        	// Read the file line-by-line
        	for(String line; (line = bufferHandle.readLine()) != null; ) {
        		// Increase the line count
        		lineCount++;
        		try {
            		// Create the JSON object
            		JSONObject json = (JSONObject) parser.parse(line);
            		// Get the list of keys
            		Object[] keys = json.keySet().toArray();
            		// Sort the list of keys
            		Arrays.sort( keys );
            		// Set the default key
            		String key = "";
            		// Set the default value
            		Object value = "";
            		// Two
            		String [][] colValList = new String[keys.length][2];
            		// Walk through the list of keys
            		for ( int i = 0; i < keys.length; i++ ) {
            			// Get the key
            			key = keys[i].toString();
            			// Try to get the corresponding value
            			if ( json.containsKey(key)) {
            				// Get the value
            				value = json.get(key);
            				// Do we have a value?
            				if ( value != null ) {
            					// Is this a stack traces?
            					if ( key.equalsIgnoreCase("stack_trace")) {
                					// Replace all "\n" with " "
            						value = ((String)value).replaceAll("\n", " ");
            					}
            				}
            				else {
            					value = null;
            				}
            			}
            			else {
            				value = "";
            			}
            			// Do we have a value?
            			if ((value != null ) && (value.toString().length() > 0 )) {
            				// Col - val pair
            				String colvalPair[] = new String[2];
            				// Save the column name
            				colvalPair[0] = key;
            				// Get the SQL definition for the key
            				SqlDef sqlDef = fieldDef.get(key);
            				// Did we find the key?
            				if (sqlDef != null) {
                				// Is it a string delimited value?
                				if(sqlDef.isString()) {
                    				// Get the value
                					String theValue = value.toString();
                					// Does it contain a double quote?
                					if(theValue.indexOf("\"") != -1) {
                						//  Replace all double quotes with a single quote
                						theValue = theValue.replaceAll("\"","\'");
                					}
                					// Is the value of type DATE?
                					if(sqlDef.isDate()) {
                						// Convert the string to a date
                						colvalPair[1] = "(STR_TO_DATE(\""+theValue+"\", \"" + PREVOTY_DATE_FORMAT + "\"))";
                					}
                					else {
                        				colvalPair[1] = "\"" + theValue + "\"";
                					}
                				}
                				else {
                    				// Save the regular value
                    				colvalPair[1] = "\"" + value.toString() + "\"";
                				}
                				// Add it to the col - val list
                				colValList[i] = colvalPair;
            				}
            				else {
            					// Did not find the Prevoty event type in fillSqlDef
            					System.out.println("Did not find the key: \"" + key + "\"");
            				}
            			}
            		}
            		// Print the record count
            		System.out.println("# Record count: " + lineCount );
            		// Print the start of the insert script
            		System.out.println("INSERT INTO "+PREVOTY_EVENT_TABLE+" (");
            		// Print the columns
            		for ( int i = 0; i < keys.length; i++ ) {
            			// Do we have a column and a value?
            			if((colValList[i][0] != null) && (colValList[i][0].length() > 0 ) && 
            			   (colValList[i][1] != null) && (colValList[i][1].length() > 0 )) {
            				// Print the column name
            				System.out.print("\t" + colValList[i][0]);
            				// Is this the last one?
            				if(i == (keys.length - 1)) {
            					// Print the end of the column list
            					System.out.println(" )\nVALUES (");
            				}
            				else {
            					// print the end of the column name
            					System.out.println(",");
            				}
            			}
            		}
            		// Print the values
            		for ( int i = 0; i < keys.length; i++ ) {
            			// Do we have a column and a value?
            			if((colValList[i][0] != null) && (colValList[i][0].length() > 0 ) && 
            			   (colValList[i][1] != null) && (colValList[i][1].length() > 0 )) {
            				// Print the value
            				System.out.print("\t" + colValList[i][1]);
            				// Is this the last one?
            				if(i == (keys.length - 1)) {
            					// Print the end of the values list
            					System.out.println(" );");
            				}
            				else {
            					// Print the end of the value
            					System.out.println(",");
            				}
            			}
            		}
        		}
        		catch (ParseException e) {
        			// There is an error in the JSON object
        			System.out.println("Could not parse the line \"" + line + "\"");
        		}
        	}
        	// Close the buffer reader
        	bufferHandle.close();
        } catch (FileNotFoundException e) {
            displayHelp("Could not find the Prevoty results log file \"" + prLogFilePath + "\"");
        } catch (IOException e) {
            displayHelp("Could not read the Prevoty results log file \"" + prLogFilePath + "\"");
        }
    }
    
    // Parse and print the Prevoty Results log file (JSON) in text format
    void runTextOutput() {
        // Try to parse the file
        try{
            // Create the file handle
        	FileReader fileHandle = new FileReader(prLogFilePath);
        	// Create the buffer handle 
        	BufferedReader bufferHandle = new BufferedReader(fileHandle);
        	// Create a JSON parser
        	JSONParser parser = new JSONParser();
        	// Line count
        	int lineCount = 0;
        	// Read the file line-by-line
        	for(String line; (line = bufferHandle.readLine()) != null; ) {
        		try {
            		// Print the line count
            		System.out.println( "\"Result " + ++lineCount + ":\"" );
            		// Create the JSON object
            		JSONObject json = (JSONObject) parser.parse(line);
            		// Get the list of keys
            		Object[] keys = json.keySet().toArray();
            		// Sort the list of keys
            		Arrays.sort( keys );
            		// Set the default key
            		String key = "";
            		// Set the default value
            		Object value = "";
            		// Walk through the list of keys
            		for ( int i = 0; i < keys.length; i++ ) {
            			// Get the key
            			key = keys[i].toString();
            			// Print the key
            			System.out.print( "\t\"" + key + "\"");
            			// Try to get the corresponding value
            			if ( json.containsKey(key)) {
            				// Get the value
            				value = json.get(key);
            				// Do we have a value?
            				if ( value != null ) {
            					// Is this a stack traces?
            					if ( key.equalsIgnoreCase("stack_trace")) {
                					// Replace all "\n" with "\"\n\t\t"
            						value = ((String)value).replaceAll("\n", "\"\n\t\t\"");
            					}
            				}
            				else {
            					value = "null";
            				}
            			}
            			else {
            				value = "";
            			}
            			// Print the value
            			System.out.println( "\t\"" + value.toString() + "\"");
            		}
        		}
                catch (ParseException e) {
                    // There is an error in the JSON object
                    System.out.println("Could not parse the line \"" + line + "\"");
                }
            }
        	// Close the buffer reader
        	bufferHandle.close();
        } catch (FileNotFoundException e) {
            displayHelp("Could not find the Prevoty results log file \"" + prLogFilePath + "\"");
        } catch (IOException e) {
            displayHelp("Could not read the Prevoty results log file \"" + prLogFilePath + "\"");
        }
    }
    
	// Print HTML header
	void printHtmlHeader() {
		System.out.println("<html>");
		System.out.println("	<head>");
		System.out.println("		<title>Prevoty Results Log</title>");
		System.out.println("		<style type=\"text/css\">");
		System.out.println("			body");
		System.out.println("			{");
		System.out.println("			  margin: 10 10 10 10;");
		System.out.println("			  padding: 10 10 10 10;");
		System.out.println("			  background-color: White;");
		System.out.println("			  color: Black;");
		System.out.println("			  font-family: Arial, Verdana, sans-serif;");
		System.out.println("			  font-size: 14px;");
		System.out.println("			  font-style: none;");
		System.out.println("			  text-decoration: none;");
		System.out.println("			}");
		System.out.println("			table");
		System.out.println("			{");
		System.out.println("			  border: .1em solid Navy;");
		System.out.println("			}");
		System.out.println("			td");
		System.out.println("			{");
		System.out.println("			  color: Black;");
		System.out.println("			  font-family: Arial, Verdana, sans-serif;");
		System.out.println("			  font-size: 14px;");
		System.out.println("			  border: .1em solid Navy;");
		System.out.println("			}");
		System.out.println("			td.stacktrace");
		System.out.println("			{");
		System.out.println("			  color: Black;");
		System.out.println("			  font-family: Courier New, Courier, monospace;");
		System.out.println("			  font-size: 14px;");
		System.out.println("			  border: .1em solid Navy;");
		System.out.println("			}");
		System.out.println("			td.category");
		System.out.println("			{");
		System.out.println("			  color: black;");
		System.out.println("			  background-color: Silver;");
		System.out.println("			  font-family: Arial, Verdana, sans-serif;");
		System.out.println("			  font-size: 14px;");
		System.out.println("			  border: .1em solid Navy;");
		System.out.println("			}");
		System.out.println("			th");
		System.out.println("			{");
		System.out.println("			  color: white;");
		System.out.println("			  background-color: Gray;");
		System.out.println("			  font-family: Arial, Verdana, sans-serif;");
		System.out.println("			  font-size: 14px;");
		System.out.println("			  font-weight: bold;");
		System.out.println("			  vertical-align: top;");
		System.out.println("			  text-align: left;");
		System.out.println("			  border: .1em solid Navy;");
		System.out.println("			}");
		System.out.println("			tr.record");
		System.out.println("			{");
		System.out.println("			  background-color: Navy;");
		System.out.println("			}");
		System.out.println("			td.record");
		System.out.println("			{");
		System.out.println("			  color: White;");
		System.out.println("			  font-family: Arial, Verdana, sans-serif;");
		System.out.println("			  font-size: 14px;");
		System.out.println("			  font-weight: bold;");
		System.out.println("			  vertical-align: top;");
		System.out.println("			  horizontal-align: left;");
		System.out.println("			  border: .1em solid Navy;");
		System.out.println("			}");
		System.out.println("		</style>");
		System.out.println("	</head>");
		System.out.println("	<body>");
		System.out.println("		<table>");
	}
	
	// Print HTML footer
	void printHtmlFooter() {
		System.out.println("		</table>");
		System.out.println("	</body>");
		System.out.println("</html>");
	}
	
	// Escape HTML characters
	private String escapeHtml(String src ) {
		// Set the default return value
		String retVal = "";
		// Do we have a source?
		if ((src != null) && (src.length() > 0)) {
			// Replace all ampersands
			retVal = src.replaceAll("&", "&amp;");
			// Replace all left angle bracket
			retVal = retVal.replaceAll("<", "&lt;");
			// Replace all right angle bracket
			retVal = retVal.replaceAll(">", "&gt;");
			// Replace all new lines with "<br>"
			retVal = retVal.replaceAll("\n", "<br>");
			// Replace all spaces with "&nbsp;"
			retVal = retVal.replaceAll(" ", "&nbsp;");
		}
		// Return the result
		return retVal;
	}
	
    // Parse and print the Prevoty Results log file (JSON) in HTML format
    void runHtmlOutput() {
        // Try to parse the file
        try{
        	// print HTML header
        	printHtmlHeader();
            // Create the file handle
        	FileReader fileHandle = new FileReader(prLogFilePath);
        	// Create the buffer handle 
        	BufferedReader bufferHandle = new BufferedReader(fileHandle);
        	// Create a JSON parser
        	JSONParser parser = new JSONParser();
        	// Line count
        	int lineCount = 0;
        	// Read the file line-by-line
        	for(String line; (line = bufferHandle.readLine()) != null; ) {
        		try {
            		// Print the line count
            		System.out.println( "\t\t\t<tr class=\"record\"><td class=\"record\" colspan=\"3\">Result " + ++lineCount + ":</td></tr>" );
            		// Create the JSON object
            		JSONObject json = (JSONObject) parser.parse(line);
            		// Get the list of keys
            		Object[] keys = json.keySet().toArray();
            		// Sort the list of keys
            		Arrays.sort( keys );
            		// Set the default key
            		String key = "";
            		// Set the default value
            		Object value = "";
            		// Walk through the list of keys
            		for ( int i = 0; i < keys.length; i++ ) {
            			// Get the key
            			key = keys[i].toString();
            			// Print the key
            			System.out.print( "\t\t\t<tr><th>" + key + "</th>");
            			// Try to get the corresponding value
            			if ( json.containsKey(key)) {
            				// Get the value
            				value = json.get(key);
            				// Do we have a value?
            				if ( value != null ) {
            					// Is this an stack_trace, input, output, uri_query, or url?
            					if (key.equalsIgnoreCase("stack_trace") || key.equalsIgnoreCase("input") || key.equalsIgnoreCase("output") || key.equalsIgnoreCase("uri_query") || key.equalsIgnoreCase("url")) {
                					// URL decode the string
            						value = myUrlDecode((String)value);
            						// Escape the HTML characters
            						value = escapeHtml((String)value);
            					}
            				}
            				else {
            					value = "null";
            				}
            			}
            			else {
            				value = "";
            			}
            			// Is this a stack trace?
            			if ( key.equalsIgnoreCase("stack_trace")) {
                			// Print the value
                			System.out.println( "<td class=\"stacktrace\">" + value.toString() + "</td></tr>");
            			}
            			else {
                			// Is this a category?
                			if ( key.equalsIgnoreCase("category")) {
                    			// Print the value
                    			System.out.println( "<td class=\"category\">" + value.toString() + "</td></tr>");
                			}
                			else {
                    			// Print the value
                    			System.out.println( "<td>" + value.toString() + "</td></tr>");
                			}
            			}
            		}
        		}
                catch (ParseException e) {
                    // There is an error in the JSON object
                    System.out.println("Could not parse the line \"" + line + "\"");
                }
        	}
        	// Close the buffer reader
        	bufferHandle.close();
        	// print HTML footer
        	printHtmlFooter();
        } catch (FileNotFoundException e) {
            displayHelp("Could not find the Prevoty results log file \"" + prLogFilePath + "\"");
        } catch (IOException e) {
            displayHelp("Could not read the Prevoty results log file \"" + prLogFilePath + "\"");
        }
    }
    
    // Parse and analyze the Prevoty Results log file (JSON)
    void runAnalysis() {
        // Try to parse the file
        try{
            // Create the file handle
        	FileReader fileHandle = new FileReader(prLogFilePath);
        	// Create the buffer handle 
        	BufferedReader bufferHandle = new BufferedReader(fileHandle);
        	// Create a JSON parser
        	JSONParser parser = new JSONParser();
        	// Keep track of the protocol
        	String protocol;
        	// Keep track of the destination
        	String destination;
        	// Keep track of the port
        	Long port;
        	// Read the file line-by-line
        	for(String line; (line = bufferHandle.readLine()) != null; ) {
        		try {
            		// Create the JSON object
            		JSONObject json = (JSONObject) parser.parse(line);
            		// Get the category
            		String category = (String) json.get("category");
            		// Determine what to do, based on the category
            		switch (stringToCategory(category)) {
    	        		case Command_Injection:
    	        			addCommandInjection((String) json.get("commandline"));
    	        			break;
    	        		case Configuration:
    	        			addConfiguration((String) json.get("timestamp"));
    	        			break;
    	        		case Content_Injection:
    	        			addContentInjection((String) json.get("url"));
    	        			break;
    	        		case Cross_Site_Request_Forgery:
    	        			addCSRF((String) json.get("uri_path") + "\t|\t" + (String) json.get("validation_message"));
    	        			break;
    	        		case Cross_Site_Scripting:
    	        			// Do we have an URI query?
    	        			String uriQuery = myUrlDecode((String) json.get("uri_query"));
    	        			if ((uriQuery != null ) && (uriQuery.length() > 0 )) {
    	        				// Add with URI query
    		        			addXSS((String) json.get("uri_path") + "&" + uriQuery);	        				
    	        			}
    	        			else {
    	        				// Do we have an input?
        	        			String input = myUrlDecode((String) json.get("input"));
        	        			if ((input != null ) && (input.length() > 0 )) {
        	        				// Add with input
        		        			addXSS((String) json.get("uri_path") + "&" + input);	        				
        	        			}
        	        			else {
        	        				// Add without URI query or input
        		        			addXSS((String) json.get("uri_path"));	        				
        	        			}
    	        			}
    	        			break;
    	        		case Database_Access_Violation:
    	        			addDatabaseAccessViolation((JSONArray) json.get("statements"));
    	        			break;
    	        		case Dependency:
    	        			addDependency((String) json.get("name") + " - " + (String) json.get("product_version"));
    	        			break;
    	        		case HTML_Injection:
    	        			addHtmlInjection(myUrlDecode((String) json.get("input")));
    	        			break;
    	        		case HTTP_Response_Splitting:
    	        			addHttpResponseSplitting((String) json.get("http_method"), (String) json.get("http_referrer"));
    	        			break;
    	        		case JSON_Injection:
    	        			addJsonInjection(myUrlDecode((String) json.get("uri_query")));
    	        			break;
    	        		case Network_Activity:
    	        			// Get the protocol
    	        			protocol = (String) json.get("network_activity_protocol");
    	        			protocol = protocol.trim().toLowerCase();
    	        			// Get the destination
    	        			destination = (String) json.get("network_activity_destination");
    	        			destination = destination.trim().toLowerCase();
    	        			// Get the port
    	        			port = (Long) json.get("network_activity_port");
    	        			addNetworkActivity(protocol + "://" + destination + ":" + port.toString());
    	        			break;
    	        		case Normal:
    	        			// Get the mode
    	        			String mode = (String) json.get("mode");
    	        			// Get the action
    	        			String action = (String) json.get("action");
    	        			// Make the first letter an upper case
    	        			action = action.substring(0, 1).toUpperCase() + action.substring(1);
    	        			// Get the engine
    	        			String engine = (String) json.get("engine"); 
    	        			// Determine what to do
    	        			switch ( stringToEngine( engine )) {
    	        				case Command:
    		        				// Add the command line
    		        				addNormal( action + " (" + mode + ") CMD: " + (String) json.get("commandline"));
    	        				break;
    	        				case Content:
    		        				// Add the URL
    		        				addNormal( action + " (" + mode + ") Content: " + (String) json.get("url"));
    	        				break;
								case Cryptography:
									// Add the Cryptography
    		        				addNormal( action + " (" + mode + ") Cryptography: " + (String) json.get("algorithm"));
									break;
    	        				case Http:
    		        				// Add the URL
    		        				addNormal( action + " (" + mode + ") HTTP: " + (String) json.get("url"));
    	        				break;
    	        				case Network:
    	    	        			// Get the protocol
    	    	        			protocol = (String) json.get("network_activity_protocol");
    	    	        			protocol = protocol.trim().toLowerCase();
    	    	        			// Get the destination
    	    	        			destination = (String) json.get("network_activity_destination");
    	    	        			destination = destination.trim().toLowerCase();
    	    	        			// Get the port
    	    	        			port = (Long) json.get("network_activity_port");
    	        					// Add the outbound traffic
    	        					addNormal( action + " (" + mode + ") Network: " + protocol + "://" + destination + ":" + port.toString());
    	        					break;
    	        				case Path:
    		        				// Add the path
    		        				addNormal( action + " (" + mode + ") PT: " + (String) json.get("path"));
    	        				break;
    	        				case Query:
    		        				// Add the query
    		        				addNormal( action + " (" + mode + ") SQL: " + (String) json.get("query"));
    	        				break;
    	        				case Token:
    		        				// Add the URL
    		        				addNormal( action + " (" + mode + ") Token: " + (String) json.get("url"));
    	        				break;
    	    	        		case Undefined:
    	    	        			displayHelp("Engine \"" + engine + "\" not implemented");
    	    	        			break;
    	        			}
    	        			break;
    	        		case Path_Traversal:
    	        			addPathTraversal((String) json.get("path"));
    	        			break;
    	        		case Request_Response:
    	        			// Not sure what to report on
    	        			break;
    	        		case Request_Size:
    	        			addRequestSize((Long) json.get("maxRequestSize"), (Long) json.get("requestSize"), (Long) json.get("requestSizeDifference"));
    	        			break;
    	        		case Unvalidated_Redirect:
    	        			addUnvalRedirect(getDomain((String) json.get("uri_query")));
    	        			break;
    	        		case Unprocessed_Query:
    	        			addUnprocessedQuery((String) json.get("query"));
    	        			break;
    	        		case XML_External_Entity:
    	        			addXmlExternalEntity(searchForTag(myUrlDecode((String) json.get("input")), "DOCTYPE"));
    	        			break;
    	        		case Uncaught_Exception:
    	        			addUncaughtException((String) json.get("exception"));
    	        			break;
    	        		case Statistics:
    	        			addStatistics((String) json.get("app"));
    	        			break;
    	        		case SQL_Injection:
    	        			addSqlInjection((String) json.get("query"));
    	        			break;
    	        		case Large_Request:
    	        			addLargeRequest((Long) json.get("requestSize"), (Long) json.get("maxRequestSize"));
    	        			break;
    	        		case Weak_Browser_Cache_Management:
    	        			addWeakBrowserCacheManagement((String) json.get("http_user_agent"));
    	        			break;
    	        		case Weak_Caching:
    	        			// Get the action
    	        			String theAction = (String) json.get("action");
    	        			if(theAction.equalsIgnoreCase("added")) {
    	        				theAction = "added a cache-control header to the response";
    	        			}
    	        			addWeakCaching(theAction);
    	        			break;
    	        		case Weak_Cryptography:
    	        			addWeakCryptography((String) json.get("algorithm"));
    	        			break;
    	        		case Undefined:
    	        			// Nothing to summarize
    	        			break;
            		}
        		}
                catch (ParseException e) {
                    // There is an error in the JSON object
                    System.out.println("Could not parse the line \"" + line + "\"");
                }
            }
        	// Close the buffer reader
        	bufferHandle.close();
        	// Print the list of CMDi issues
            printSortedHashMap("Command Injection (CMDi)", commandInjectionMap, true, true);
        	// Print the list of Configurations
            printSortedHashMap("Configuration", configurationMap, true, true);
        	// Print the list of Content Injection issues
            printSortedHashMap("Content Injection", contentInjectionMap, true, true);
        	// Print the list of CSRF issues
            printSortedHashMap("Cross-Site Request Forgery (CSRF)", csrfMap, true, true);
        	// Print the list of XSS issues
            printSortedHashMap("Cross-Site Scripting (XSS)", xssMap, true, true);
            // Print the list of Database Access Violations
            printSortedHashMap("Database Access Violations", databaseAccessViolationMap, true, true);
            // Print the list of Dependencies
            printSortedHashMap("Dependency", dependencyMap, true, true);
        	// Print the list of HTML Injection
            printSortedHashMap("HTML Injection (HTMLi)", htmlInjectionMap, true, true);
        	// Print the list of HTTP Response Splitting
            printSortedHashMap("HTTP Response Splitting", httpResponseSplittingMap, true, true);
        	// Print the list of JSON Injection
            printSortedHashMap("JSON Injection (JSONi)", jsonInjectionMap, true, true);
        	// Print the list of Large Requests
            printSortedHashMap("Large Request", largeRequestMap, true, true);
            // Print the network activity
            printSortedHashMap("Network Activity", networkActivityMap, true, true);
        	// Print the list of normal
            printSortedHashMap("Normal", normalMap, true, true);       
            // Print the list of PT issues
            printSortedHashMap("Path Traversal (PT)", pathTraversalMap, true, true);
            // Print the list of request size issues
            printSortedHashMap("Request Size", requestSizeMap, true, true);
        	// Print the list of Statistics
            printSortedHashMap("Statistics", statisticsMap, true, true);
        	// Print the list of SQLi issues
            printSortedHashMap("SQL Injection (SQLi)", sqlInjectionMap, true, true);
        	// Print the list of Uncaught Exceptions
            printSortedHashMap("Uncaught Exceptions", uncaughtExceptionMap, true, true);
        	// Print the list of Unprocessed Queries
            printSortedHashMap("Unprocessed Query", unprocessedQueryMap, true, true);
        	// Print the list of Unvalidated Redirects
            printSortedHashMap("Unvalidated Redirect", unvalRedirectMap, true, true);
        	// Print the list of Weak Browser Cache Management
            printSortedHashMap("Weak Browser Cache Management", weakBrowserCacheManagementMap, true, true);
        	// Print the list of Weak Caching
            printSortedHashMap("Weak Caching", weakCachingMap, true, true);
        	// Print the list of Weak Cryptography
            printSortedHashMap("Weak Cryptography", weakCryptographyMap, true, true);
        	// Print the list of XML External Entities
            printSortedHashMap("XML External Entity", xmlExternalEntityMap, true, true);
        } catch (FileNotFoundException e) {
            displayHelp("Could not find the Prevoty results log file \"" + prLogFilePath + "\"");
        } catch (IOException e) {
            displayHelp("Could not read the Prevoty results log file \"" + prLogFilePath + "\"");
        }
    }
    
    // If the severity is either medium, critical, or high then we need to optimize
    boolean optimizeThis( String severity ) {
    	// Set the default return value
    	boolean retVal = false;
    	// Is the severity medium
    	if ( severity.equalsIgnoreCase("medium")) {
    		retVal = true;
    	}
    	else {
        	// Is the severity high
        	if ( severity.equalsIgnoreCase("high")) {
        		retVal = true;
        	}
        	else {
            	// Is the severity critical
            	if ( severity.equalsIgnoreCase("critical")) {
            		retVal = true;
            	}
        	}
    	}
    	// Return the result
    	return retVal;
    }
    
    // In the case where nothing was done or found, report it
    void printAnthingDone(String actionName, int nofActions, String message) {
    	// Nothing was done?
    	if(nofActions == 0) {
    		// Let the user know
        	System.out.println("╔══════════════════════════════════════════════════════╗");
        	actionName = extendStr(false, " ", 55, "║ " + actionName + ": ") + "║";
        	System.out.println(actionName);
        	System.out.println("╚══════════════════════════════════════════════════════╝");
        	System.out.println(" " + message);
    	}
    }
    
    // Add a key to a list of strings
    private String [] addKeyToList(String [] list, String key ) {
    	// Set the default return value
    	String [] retVal = null;
    	// Do we have a list?
    	if((list != null) && (list.length > 0)) {
    		// Create a new list, one element bigger then list
    		retVal = new String[list.length+1];
    		// Copy each key from the list
    		for(int index=0; index<list.length; index++) {
    			// Copy the existing keys
    			retVal[index] = list[index];
    		}
    		// Copy the new key
    		retVal[list.length] = key;
    	}
    	else {
    		// Create a new list
    		retVal = new String[1];
    		// Copy the key
    		retVal[0] = key;
    	}
    	// Return the result
    	return retVal;
    }
    
    // Get the list of attributes from input
    String getAttributes(String input ) {
    	// Set the default return value
    	String retVal = "";
    	// List of attributes
    	String [] attrList = null;
    	// Do we have an input?
    	if((input != null) && (input.length() > 0 )) {
    		// Track whether or not we are in a attribute
    		boolean inAttr = true;
    		// Get the length of the string
    		int length = input.length();
    		// Track current character
    		char key;
    		// Track the attribute
    		String attr = "";
    		// Parse through the input
    		for(int index = 0; index < length; index++ ) {
    			// Get the character at the index
    			key = input.charAt(index);
    			// Are we in an attribute?
    			if(inAttr) {
    				// If the character is an equal sign we reached the end of the attribute and should jump out of it
    				if(key == '=') {
    					// Jump out of the attribute search
    					inAttr = false;
    					// Add the attribute to the list
    					attrList = addKeyToList(attrList, attr);
    					// Clear the tag
    					attr = "";
    				}
    				else {
    					if((key == ' ') || (key == '"')) {
    						// We thought we were in an attribute, but we were not, so jump out of the attribute search and do not add the attribute
        					inAttr = false;
        					// Clear the tag
        					attr = "";
    					}
    					else {
        					// Add the character to the attribute
        					attr += key;
    					}
    				}
    			}
				else {
					// If the character is a space, then the next character could be the beginning of an attribute
					if(key == ' ') {
						// We are in an attribute
						inAttr = true;
					}
				}
    		}	
    	}    	
    	// Do we have a list of attributes?
    	if((attrList != null) && (attrList.length > 0)) {
    		// Sort the list
    		Arrays.sort(attrList);
    		// Track the attribute to prevent duplication
    		String attr = "";
    		// Put them all together as one string, separated by commas
    		for(int index=0; index<attrList.length; index++) {
    			// Is the attribute different from the previous one?
    			if(!attrList[index].equalsIgnoreCase(attr)) {
    				// Do we need to add a comma?
    				if((retVal!=null) && (retVal.length() > 0 )) {
    					// Add a comma
    					retVal += ", ";
    				}
        			// Add the string
        			retVal += attrList[index];
        			// Copy the attribute
        			attr = attrList[index];
    			}
    		}
    	}
    	// Return the result
    	return retVal;
    }
    
    // Construct the JSON content policy for the HTML tages
    String getJsonContentPolicy(String results, String htmlTag, String htmlAttrs) {
    	// Do we have an HTML tag?
    	if((htmlTag != null ) && (htmlTag.length() > 0)) {
    		// Do we have HTML attributes?
    		if((htmlAttrs != null) && (htmlAttrs.length() > 0)) {
    			// Do we already have a list?
    			if(results.length() > 0 ) {
    				// Jump to the next line
    				results += ",\n";
    			}
    			// Add the HTML tag
    			results += "  \"" + htmlTag + "\": {\n      \"Attributes\": [\n";
    			// Split the list of attributes
    			String [] attrs = htmlAttrs.split(",");
    			// The number of attributes
    			int nofAttrs = attrs.length;
    			// Parse through the list of attributes
    			for(int index=0; index<nofAttrs; index++) {
    				// Add the attribute
    				results += "          \"" + attrs[index] + "\"";
    				// Is this not the last attribute?
    				if (index < (nofAttrs - 1)) {
    					// Add a comma
    					results += ",";
    				}
    				// Add a new line
    				results += "\n";
    			}
    			// Add the trailing part of the JSON policy
    			results += "      ],\n      \"ForcedAttributes\": {}\n  }";
    		}
    		else {
    			// Do we already have a list?
    			if(results.length() > 0 ) {
    				// Jump to the next line
    				results += ",\n";
    			}
    			// Add the HTML tag only
    			results += "  \"" + htmlTag + "\": {\n      \"Attributes\": [],\n      \"ForcedAttributes\": {}\n  }";
    		}
    	}
    	// Return the result
    	return results;
    }
    
    // Get list of HTML tags from input
    String getHtmlTags(String input) {
    	// Set the default return value
    	String retVal = "";
		// List of HTML tags
		String [] htmlTagList = null;
    	// Do we have an input?
    	if((input != null) && (input.length() > 0 )) {
    		// Track whether or not we are in a tag
    		boolean inTag = false;
    		// Get the length of the string
    		int length = input.length();
    		// Track current character
    		char key;
    		// Track the tag
    		String tag = "";
    		// Track the list of attributes
    		String attributes = "";
    		// Parse through the input
    		for(int index = 0; index < length; index++ ) {
    			// Get the character at the index
    			key = input.charAt(index);
    			// Are we in a tag?
    			if(inTag) {
    				// If the character is a / we are in a closing tag and should jump out of it
    				if(key == '/') {
    					// Jump out of the tag search
    					inTag = false;
    					// Clear the tag
    					tag = "";
    				}
    				else {
    					// If the character is a > we reach the end of the opening tag and should add it to the list of tags
    					if(key == '>'){
        					// Jump out of the tag search
        					inTag = false;
        					
        					// Create the JSON policy for this tag
        					// retVal = getJsonContentPolicy(retVal, tag, "");
        					
        					// Add the HTML tag, without attributes to the list of HTML tags
        					htmlTagList = addKeyToList(htmlTagList, tag);
        					// Reset the tag
        					tag = "";
    					}
    					else {
    						// If the character is a space we hit an attribute
    						if(key == ' ') {
    							// Get the string from the current position through the end
    							String subStr = input.substring(index+1, length-1);
    							// Get the list of attributes from the substring till the next angle bracket or end of the string
    							int endIndex = subStr.indexOf('>');
    							if(endIndex != -1 ) {
    								attributes = getAttributes(subStr.substring(0, subStr.indexOf('>')));
    							}
    							else {
    								attributes = getAttributes(subStr.substring(0, subStr.length()-1));
    							}
            					
            					// Add the HTML tag, without attributes to the list of HTML tags
            					htmlTagList = addKeyToList(htmlTagList, tag+" ("+attributes+")");

            					// Jump out of the tag search
            					inTag = false;
            					// Reset the tag
            					tag = "";
    						}
        					else {
        						// Add the character to the tag
        						tag += key;
        					}
    					}
    				}
    			}
    			else {
    				//If the character is a < we enter a opening- or a closing tag
    				if(key == '<') {
    					// We are in a tag
    					inTag = true;
    				}
    			}
    		}
    	}
    	// Do we have an HTML tag list?
    	if((htmlTagList != null) && (htmlTagList.length > 0)) {
    		// Sort the list
    		Arrays.sort(htmlTagList);
    		// Track the HTML tag
    		String htmlTag = "";
    		// Put them all together as one string, separated by commas
    		for(int index=0; index<htmlTagList.length; index++) {
    			// Is this HTML tag different from the previous one?
    			if(!htmlTagList[index].equalsIgnoreCase(htmlTag)) {
    				// Do we need to add a comma?
    				if((retVal!=null) && (retVal.length() > 0 )) {
    					// Add a comma
    					retVal += ", ";
    				}
        			// Add the string
        			retVal += htmlTagList[index];
        			// Copy the HTML tag to prevent duplication
        			htmlTag = htmlTagList[index];
    			}
    		}
    	}
    	// Return the result
    	return retVal;
    }
    
    // Parse and analyze the Prevoty Results log file (JSON) or configuration optimization
    void runOptimization() {
    	// Track the number of optimizations
    	int nofOptimization = 0;
        // Try to parse the file
        try{
            // Create the file handle
        	FileReader fileHandle = new FileReader(prLogFilePath);
        	// Create the buffer handle 
        	BufferedReader bufferHandle = new BufferedReader(fileHandle);
        	// Create a JSON parser
        	JSONParser parser = new JSONParser();
        	// Read the file line-by-line
        	for(String line; (line = bufferHandle.readLine()) != null; ) {
        		try {
            		// Create the JSON object
            		JSONObject json = (JSONObject) parser.parse(line);
            		// Get the category
            		String category = (String) json.get("category");
            		// Get the severity
            		String severity = (String) json.get("severity");
            		// Do we need to look at this?
            		boolean investigate = optimizeThis( severity );
            		// Should we even look at this for optimization?
            		if ( investigate ) {
            			// Increase the number of optimizations
            			nofOptimization++;
                		// Determine what to do, based on the category
                		switch (stringToCategory(category)) {
        	        		case Command_Injection:
        	        			addCommandInjection((String) json.get("commandline"));
        	        			break;
        	        		case Configuration:
        	        			// Nothing to optimize
        	        			break;
        	        		case Content_Injection:
        	        			addContentInjection((String) json.get("url"));
        	        			break;
        	        		case Cross_Site_Request_Forgery:
        	        			addCSRF((String) json.get("uri_path"));
        	        			break;
        	        		case Cross_Site_Scripting:
        	        			// Do we have an URI query?
        	        			String uriQuery = myUrlDecode((String) json.get("uri_query"));
        	        			if ((uriQuery != null ) && (uriQuery.length() > 0 )) {
        	        				// Add with URI query
        		        			addXSS((String) json.get("uri_path") + "&" + uriQuery);	        				
        	        			}
        	        			else {
        	        				// Do we have an input?
            	        			String input = myUrlDecode((String) json.get("input"));
            	        			if ((input != null ) && (input.length() > 0 )) {
            	        				// Add with input
            		        			addXSS((String) json.get("uri_path") + "&" + input);	        				
            	        			}
            	        			else {
            	        				// Add without URI query or input
            		        			addXSS((String) json.get("uri_path"));	        				
            	        			}
        	        			}
        	        			break;
        	        		case Database_Access_Violation:
        	        			addDatabaseAccessViolation((JSONArray) json.get("statements"));
        	        			break;
        	        		case Dependency:
        	        			// Nothing to optimize
        	        			break;
        	        		case HTML_Injection:
        	        			addHtmlInjection(getHtmlTags( myUrlDecode((String) json.get("input"))));
        	        			break;
        	        		case HTTP_Response_Splitting:
        	        			addHttpResponseSplitting((String) json.get("http_method"), (String) json.get("http_referrer"));
        	        		case JSON_Injection:
        	        			addJsonInjection(myUrlDecode((String) json.get("uri_query")));
        	        			break;
        	        		case Large_Request:
        	        			addLargeRequest((Long) json.get("requestSize"), (Long) json.get("maxRequestSize"));
        	        			break;
    						case Network_Activity:
        	        			// Get the protocol
        	        			String protocol = (String) json.get("network_activity_protocol");
        	        			protocol = protocol.trim().toLowerCase();
        	        			// Get the destination
        	        			String destination = (String) json.get("network_activity_destination");
        	        			destination = destination.trim().toLowerCase();
        	        			// Get the port
        	        			Long port = (Long) json.get("network_activity_port");
        	        			addNetworkActivity(protocol + "://" + destination + ":" + port.toString());
    							break;
        	        		case Normal:
        	        			// Nothing to optimize
        	        			break;
        	        		case Path_Traversal:
        	        			addPathTraversal((String) json.get("path"));
        	        			break;
        	        		case Request_Response:
        	        			// Not sure what to optimize
        	        			break;
        	        		case Request_Size:
        	        			addRequestSize((Long) json.get("maxRequestSize"), (Long) json.get("requestSize"), (Long) json.get("requestSizeDifference"));
        	        			break;
        	        		case Statistics:
        	        			// Nothing to optimize
        	        			break;
        	        		case SQL_Injection:
        	        			addSqlInjection((String) json.get("query"));
        	        			break;
        	        		case Unvalidated_Redirect:
        	        			addUnvalRedirect(getDomain((String) json.get("uri_query")));
        	        			break;
        	        		case Unprocessed_Query:
        	        			addUnprocessedQuery((String) json.get("query"));
        	        			break;
        	        		case XML_External_Entity:
        	        			addXmlExternalEntity(searchForTag(myUrlDecode((String) json.get("input")), "DOCTYPE"));
        	        			break;
        	        		case Uncaught_Exception:
        	        			addUncaughtException((String) json.get("exception"));
        	        			break;
        	        		case Weak_Browser_Cache_Management:
        	        			addWeakBrowserCacheManagement((String) json.get("http_user_agent"));
        	        			break;
        	        		case Weak_Caching:
        	        			// Nothing to optimize
        	        			break;
        	        		case Weak_Cryptography:
        	        			addWeakCryptography((String) json.get("algorithm"));
        	        			break;
        	        		case Undefined:
        	        			// Nothing to optimize
        	        			break;
						default:
							break;
                		}
            		}
        		}
                catch (ParseException e) {
                    // There is an error in the JSON object
                    System.out.println("Could not parse the line \"" + line + "\"");
                }
            }
        	// Close the buffer reader
        	bufferHandle.close();
        	// Was there anything to optimize?
        	printAnthingDone("Optimization", nofOptimization, "Nothing was found with a severity of medium, critical, or high");
        	// Print the list of CMDi issues
            printSortedHashMap("Command Injection (CMDi)", commandInjectionMap, true, true);
        	// Print the list of Content Injection issues
            printSortedHashMap("Content Injection", contentInjectionMap, true, true);
        	// Print the list of CSRF issues
            printSortedHashMap("Cross-Site Request Forgery (CSRF)", csrfMap, true, true);
        	// Print the list of XSS issues
            printSortedHashMap("Cross-Site Scripting (XSS)", xssMap, true, true);
            // Print the list of Database Access Violations
            printSortedHashMap("Database Access Violations", databaseAccessViolationMap, true, true);
        	// Print the list of HTML Injection
            printSortedHashMap("HTML Injection (HTMLi)", htmlInjectionMap, false, true);
        	// Print the list of HTTP Response Splitting
            printSortedHashMap("HTTP Response Splitting", httpResponseSplittingMap, true, true);
        	// Print the list of JSON Injection
            printSortedHashMap("JSON Injection (JSONi)", jsonInjectionMap, true, true);
        	// Print the list of Large Requests
            printSortedHashMap("Large Request", largeRequestMap, true, true);
            // Print the network activity
            printSortedHashMap("Network Activity", networkActivityMap, true, true);
            // Print the list of PT issues
            printSortedHashMap("Path Traversal (PT)", pathTraversalMap, true, true);
            // Print the list of request size issues
            printSortedHashMap("Request Size", requestSizeMap, true, true);
        	// Print the list of SQLi issues
            printSortedHashMap("SQL Injection (SQLi)", sqlInjectionMap, true, true);
        	// Print the list of Uncaught Exceptions
            printSortedHashMap("Uncaught Exceptions", uncaughtExceptionMap, true, true);
        	// Print the list of Unprocessed Queries
            printSortedHashMap("Unprocessed Query", unprocessedQueryMap, true, true);
        	// Print the list of Unvalidated Redirects
            printSortedHashMap("Unvalidated Redirect", unvalRedirectMap, true, true);
        	// Print the list of Weak Browser Cache Management
            printSortedHashMap("Weak Browser Cache Management", weakBrowserCacheManagementMap, true, true);
        	// Print the list of Weak Caching
            printSortedHashMap("Weak Caching", weakCachingMap, true, true);
        	// Print the list of Weak Cryptography
            printSortedHashMap("Weak Cryptography", weakCryptographyMap, true, true);
        	// Print the list of XML External Entities
            printSortedHashMap("XML External Entity", xmlExternalEntityMap, true, true);
        } catch (FileNotFoundException e) {
            displayHelp("Could not find the Prevoty results log file \"" + prLogFilePath + "\"");
        } catch (IOException e) {
            displayHelp("Could not read the Prevoty results log file \"" + prLogFilePath + "\"");
        }
    }

    // Initialize the object
    private void init() {
    	// Initialize the engine map
    	engineMap.put("command",      Engine.Command);
    	engineMap.put("content",      Engine.Content);
    	engineMap.put("cryptography", Engine.Cryptography);
    	engineMap.put("http",         Engine.Http);
    	engineMap.put("path",         Engine.Path);
    	engineMap.put("query",        Engine.Query);
    	engineMap.put("token",        Engine.Token);
    	engineMap.put("network",      Engine.Network);
    	// Initialize the category map
    	categoryMap.put("command injection",             Category.Command_Injection);
    	categoryMap.put("configuration",                 Category.Configuration);
    	categoryMap.put("content injection",             Category.Content_Injection);
    	categoryMap.put("cross-site request forgery",    Category.Cross_Site_Request_Forgery);
    	categoryMap.put("cross-site scripting",          Category.Cross_Site_Scripting);
    	categoryMap.put("database access violation",     Category.Database_Access_Violation);
    	categoryMap.put("dependency",                    Category.Dependency);
    	categoryMap.put("html injection",                Category.HTML_Injection);
    	categoryMap.put("http response splitting",       Category.HTTP_Response_Splitting);
    	categoryMap.put("json injection",                Category.JSON_Injection);
    	categoryMap.put("large request",                 Category.Large_Request);
    	categoryMap.put("network activity",              Category.Network_Activity);
    	categoryMap.put("normal",                        Category.Normal);
    	categoryMap.put("path traversal",                Category.Path_Traversal);
    	categoryMap.put("request / response",            Category.Request_Response);
    	categoryMap.put("request size",                  Category.Request_Size);
    	categoryMap.put("statistics",                    Category.Statistics);
    	categoryMap.put("sql injection",                 Category.SQL_Injection);
    	categoryMap.put("uncaught exception",            Category.Uncaught_Exception);
    	categoryMap.put("unprocessed query",             Category.Unprocessed_Query);
    	categoryMap.put("unvalidated redirect",          Category.Unvalidated_Redirect);
    	categoryMap.put("weak browser cache management", Category.Weak_Browser_Cache_Management);
    	categoryMap.put("weak caching",                  Category.Weak_Caching);
    	categoryMap.put("weak cryptography",             Category.Weak_Cryptography);
    	categoryMap.put("xml external entity",           Category.XML_External_Entity);
    }
    
    // Parse and analyze the Prevoty Results log file (JSON)
    private void run() {
    	// Determine what to do
    	switch ( theAction ) {
	    	case Analyze:
	    		runAnalysis();
	    		break;
	    	case Html_Ouput:
	    		runHtmlOutput();
	    		break;
	    	case Optimization:
	    		runOptimization();
	    		break;
	    	case Summary:
	    		runSummary();
	    		break;
	    	case Text_Output:
	    		runTextOutput();
	    		break;
	    	case Sql_Output:
	    		runSqlOutput();
	    		break;
	    	case Undefined:
	    		displayHelp("Unknown action specified");
	    		break;
    	}
    }
    
    // Main routine
    public static void main(String[] args) {
        // Create the object
        ScanLog scanLogs = new ScanLog(args);
        scanLogs.init();
        scanLogs.run();
    }
}
