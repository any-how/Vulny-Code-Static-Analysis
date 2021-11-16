#!/usr/bin/python
# -*- coding: utf-8 -*-

# rules
patchRules = {
"RCE":'''//==CTF==
$pattern = "`|var_dump|str_rot13|serialize|base64_encode|base64_decode|strrev|eval\(|assert|file_put_contents|fwrite|curl_exec\(|dl\(|readlink|popepassthru|preg_replace|create_function|array_map|call_user_func|array_filter|usort|stream_socket_server|pcntl_exec|passthru|exec\(|system\(|chroot\(|scandir\(|chgrp\(|shell_exec|proc_open|proc_get_status|popen\(|ini_alter|ini_restore|LD_PRELOAD|ini_set|base64 -d"; 
if(preg_match("/".$pattern."/is",{0})== 1){{ 
    die();
}}
//==CTF==
''',
"SQLI":'''//==CTF==
$filetr = "drop |dumpfile\b|INTO FILE|union select|outfile\b|load_file\b|multipoint\(";
$filter = "regexp|from|count|procedure|and|ascii|substr|substring|left|right|union|if|case|pow|exp|order|sleep|benchmark|into|load|outfile|dumpfile|load_file|join|show|select|update|set|concat|delete|alter|insert|create|union|or|drop|not|for|join|is|between|group_concat|like|where|user|ascii|greatest|mid|substr|left|right|char|hex|ord|case|limit|conv|table|mysql_history|flag|count|rpad|\&|\*|\.|-"; 
if(preg_match("/".$filter."/is",{0})== 1){{ 
    die(); 
}}
//==CTF==
''',
"LFI":'''//==CTF==
$pattern = "\/|flag|\.\.\/|etc|var|php|jpg|jpeg|png|bmp|gif|file|http|ftp|php|zlib|data|glob|phar|ssh2|rar|ogg|expect|zip|compress|filter|input|pearcmd"; 
if(preg_match("/".$pattern."/is",{0})== 1){{
    die(); 
}}
//==CTF==
''',
"XXE":'''//==CTF==
libxml_disable_entity_loader(true);
//==CTF==
''',
}

# path              : mytest//exec.php
# payload           : ['shell_exec', 'Remote Command Execution', ['escapeshellarg', 'escapeshellcmd']]
# vuln_content      : ['', '$target', '']
# line_vuln         : 3
# declaration_text  : $target =  $_REQUEST['target']);
# line              : 2
# vulnerable_var[1] : $target
# occurence         : 1
# plain             : True
def patch_php(path, type, line, vulnerable_var):
    fp = open(path,'r')       
    lines = []
    for index in fp:                  #内置的迭代器, 效率很高
        lines.append(index)
    fp.close()

    if type in patchRules:
        waf_rule = patchRules[type]
    else:
        return 0

    new_content = waf_rule.format(vulnerable_var)
    print(new_content)

    lines.insert(line, new_content) #插入
    s = ''.join(lines)
    fp = open(path, 'w')
    fp.write(s)
    fp.close()


#patch_php("mytest//exec.php","SQLI",4,"$target")
