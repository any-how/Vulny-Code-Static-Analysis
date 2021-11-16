#!/usr/bin/python
# -*- coding: utf-8 -*-

# /!\ Detection Format (.*)function($vuln)(.*) matched by payload[0]+regex_indicators
regex_indicators = '\\((.*?)(\\$_GET\\[.*?\\]|\\$_FILES\\[.*?\\]|\\$_POST\\[.*?\\]|\\$_REQUEST\\[.*?\\]|\\$_COOKIES\\[.*?\\]|\\$_SESSION\\[.*?\\]|\\$(?!this|e-)[a-zA-Z0-9_]*)(.*?)\\)'

# Function_Name:String, Vulnerability_Name:String, Protection_Function:Array
payloads = [

    # RCE
    ["eval", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["popen", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["popen_ex", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["system", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["passthru", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["exec", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["shell_exec", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["pcntl_exec", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["assert", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["proc_open", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["expect_popen", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["create_function", "RCE", ["escapeshellarg", "escapeshellcmd"]],
    ["call_user_func", "RCE", []],
    ["call_user_func_array", "RCE", []],
    ["preg_replace", "RCE", ["preg_quote"]],
    ["ereg_replace", "RCE", ["preg_quote"]],
    ["eregi_replace", "RCE", ["preg_quote"]],
    ["mb_ereg_replace", "RCE", ["preg_quote"]],
    ["mb_eregi_replace", "RCE", ["preg_quote"]],

    # LFI
    ["virtual", "LFI", []],
    ["include", "LFI", []],
    ["require", "LFI", []],
    ["include_once", "LFI", []],
    ["require_once", "LFI", []],
    
    # PathTraversal
    ["readfile", "PathTraversal", []],
    ["file_get_contents", "PathTraversal", []],
    ["file_put_contents", "PathTraversal", []],
    ["show_source", "PathTraversal", []],
    ["fopen", "PathTraversal", []],
    ["file", "PathTraversal", []],
    ["fpassthru", "PathTraversal", []],
    ["gzopen", "PathTraversal", []],
    ["gzfile", "PathTraversal", []],
    ["gzpassthru", "PathTraversal", []],
    ["readgzfile", "PathTraversal", []],
    ["highlight_file", "PathTraversal", []],
    ["unlink", "PathTraversal", []],
    
    ["DirectoryIterator", "PathTraversal", []],
    ["stream_get_contents", "PathTraversal", []],
    ["copy", "PathTraversal", []],

    # MySQL(i) SQLI
    ["mysql_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli_multi_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli_send_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli_master_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli_master_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysql_unbuffered_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysql_db_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli::real_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli_real_query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli::query", "SQLI", ["mysql_real_escape_string"]],
    ["mysqli_query", "SQLI", ["mysql_real_escape_string"]],

    # Postgre SQLI
    ["pg_query", "SQLI", ["pg_escape_string", "pg_pconnect", "pg_connect"]],
    ["pg_send_query", "SQLI", ["pg_escape_string", "pg_pconnect", "pg_connect"]],

    # SQLite SQLI
    ["sqlite_array_query", "SQLI", ["sqlite_escape_string"]],
    ["sqlite_exec", "SQLI", ["sqlite_escape_string"]],
    ["sqlite_query", "SQLI", ["sqlite_escape_string"]],
    ["sqlite_single_query", "SQLI", ["sqlite_escape_string"]],
    ["sqlite_unbuffered_query", "SQLI", ["sqlite_escape_string"]],

    # PDO SQLI
    ["->arrayQuery", "SQLI", ["->prepare"]],
    ["->query", "SQLI", ["->prepare"]],
    ["->queryExec", "SQLI", ["->prepare"]],
    ["->singleQuery", "SQLI", ["->prepare"]],
    ["->querySingle", "SQLI", ["->prepare"]],
    ["->exec", "SQLI", ["->prepare"]],
    ["->execute", "SQLI", ["->prepare"]],
    ["->unbufferedQuery", "SQLI", ["->prepare"]],
    ["->real_query", "SQLI", ["->prepare"]],
    ["->multi_query", "SQLI", ["->prepare"]],
    ["->send_query", "SQLI", ["->prepare"]],

    # Cubrid SQLI
    ["cubrid_unbuffered_query", "SQLI", ["cubrid_real_escape_string"]],
    ["cubrid_query", "SQLI", ["cubrid_real_escape_string"]],

    # MSSQL SQLI : Warning there is not any real_escape_string
    ["mssql_query", "SQLI", ["mssql_escape"]],

    # FileUpload
    ["move_uploaded_file", "FileUpload", []],

    # Cross Site Scripting
    # ["echo", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["print", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["printf", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["vprintf", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["trigger_error", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["user_error", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["odbc_result_all", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["ifx_htmltbl_result", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["die", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["exit", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],
    # ["var_dump", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"]],

    # XPATH and LDAP
    # ["xpath", "XPATH Injection", []],
    # ["ldap_search", "LDAP Injection", ["Zend_Ldap", "ldap_escape"]],

    # Insecure E-Mail
    # ["mail", "Insecure E-mail", []],

    # PHP unserialize
    ["unserialize", "unserialize", []],

    # Header Injection
    # ["header", "Header Injection", []],
    # ["HttpMessage::setHeaders", "Header Injection", []],
    # ["HttpRequest::setHeaders", "Header Injection", []],

    # URL Redirection
    # ["http_redirect", "URL Redirection", []],
    # ["HttpMessage::setResponseCode", "URL Redirection", []],

    # SSTI
    ["->render", "SSTI", []],
    ["->assign", "SSTI", []],
    ["->fetch", "SSTI", []], #文件包含
    
    # Weak Cryptographic Hash
    # ["md5", "Weak Cryptographic Hash", []],
    # ["sha1", "Weak Cryptographic Hash", []],

    # # Insecure Weak Random
    # ["mt_rand", "Insecure Weak Random", []],
    # ["srand", "Insecure Weak Random", []],
    # ["uniqid", "Insecure Weak Random", []],

    # Information Leak
    # ["phpinfo", "Information Leak", []],
    # ["debug_print_backtrace", "Information Leak", []],
    # ["show_source", "Information Leak", []],
    # ["highlight_file", "Information Leak", []],

    # SSRF
    ["curl_setopt", "SSRF", []],
    ["curl_exec", "SSRF", []],
    ["fsockopen", "SSRF", []],


    # XXE
    ["SimpleXMLElement", "XXE", []],
    ["xmlparse", "XXE", []],
    ["loadXML", "XXE", []],
    ["simplexml_load_string", "XXE", []],

    # Others
    ["unlink", "Arbitrary File Deletion", []],
    ["extract", "Arbitrary Variable Overwrite", []],
    ["setcookie", "Arbitrary Cookie", []],
    ["chmod", "Arbitrary File Permission", []],
    ["mkdir", "Arbitrary Folder Creation", []],
    
]
