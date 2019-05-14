
# Phpinfo-arrayzer
Make array from phpinfo.

## Use

    $php = new phpinfo;  
      
    print_r($php::all());

 - Result
```text
     Array
    (
        [General] => Array
            (
                [System] => Windows NT ******** 10.0 build 17763 (Windows 10) AMD64
                [Build Date] => Apr  2 2019 21:50:45
                [Compiler] => MSVC15 (Visual C++ 2017)
                [Architecture] => x64
                [Configure Command] => cscript /nologo configure.js  &quot; --enable-snapshot-build&quot;  &quot; --enable-debug-pack&quot;  &quot; --with-pdo-oci=c:\php-snap-build\deps_aux\oracle\x64\instantclient_12_1\sdk,shared&quot;  &quot; --with-oci8-12c=c:\php-snap-build\deps_aux\oracle\x64\instantclient_12_1\sdk,shared&quot;  &quot; --enable-object-out-dir=../obj/&quot;  &quot; --enable-com-dotnet=shared&quot;  &quot; --without-analyzer&quot;  &quot; --with-pgo&quot;
                [Server API] => Apache 2.0 Handler
                [Virtual Directory Support] => enabled
                [Configuration File (php.ini) Path] => C:\WINDOWS
                [Loaded Configuration File] => C:\wamp\bin\apache\apache2.4.39\bin\php.ini
                [Scan this dir for additional .ini files] => (none)
                [Additional .ini files parsed] => (none)
                [PHP API] => 20180731
                [PHP Extension] => 20180731
                [Zend Extension] => 320180731
                [Zend Extension Build] => API320180731,TS,VC15
                [PHP Extension Build] => API20180731,TS,VC15
                [Debug Build] => no
                [Thread Safety] => enabled
                [Thread API] => Windows Threads
                [Zend Signal Handling] => disabled
                [Zend Memory Manager] => enabled
                [Zend Multibyte Support] => provided by mbstring
                [IPv6 Support] => enabled
                [DTrace Support] => disabled
                [Registered PHP Streams] => php, file, glob, data, http, ftp, zip, compress.zlib, compress.bzip2, https, ftps, phar
                [Registered Stream Socket Transports] => tcp, udp, ssl, tls, tlsv1.0, tlsv1.1, tlsv1.2
                [Registered Stream Filters] => convert.iconv.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, zlib.*, bzip2.*
            )

        [Configuration] => Array
            (
                [allow_url_fopen] => On
                [allow_url_include] => Off
                [arg_separator.input] => &amp;
                [arg_separator.output] => &amp;
                [auto_append_file] => no value
                [auto_globals_jit] => Off
                [auto_prepend_file] => no value
                [browscap] => no value
                [default_charset] => UTF-8
                [default_mimetype] => text/html
                [disable_classes] => no value
                [disable_functions] => no value
                [display_errors] => On
                [display_startup_errors] => On
                [doc_root] => no value
                [docref_ext] => no value
                [docref_root] => no value
                [enable_dl] => Off
                [enable_post_data_reading] => On
                [error_append_string] => no value
                [error_log] => c:/wamp/logs/php_error.log
                [error_prepend_string] => no value
                [error_reporting] => 32767
                [expose_php] => On
                [extension_dir] => c:/wamp/bin/php/php7.3.4/ext/
                [file_uploads] => On
                [hard_timeout] => 2
                [highlight.comment] => #FF8000
                [highlight.default] => #0000BB
                [highlight.html] => #000000
                [highlight.keyword] => #007700
                [highlight.string] => #DD0000
                [html_errors] => On
                [ignore_repeated_errors] => Off
                [ignore_repeated_source] => Off
                [ignore_user_abort] => Off
                [implicit_flush] => Off
                [include_path] => .; C:\php\pear
                [input_encoding] => no value
                [internal_encoding] => no value
                [log_errors] => On
                [log_errors_max_len] => 1024
                [mail.add_x_header] => Off
                [mail.force_extra_parameters] => no value
                [mail.log] => no value
                [max_execution_time] => 0
                [max_file_uploads] => 20
                [max_input_nesting_level] => 64
                [max_input_time] => 60
                [max_input_vars] => 2500
                [memory_limit] => 1G
                [open_basedir] => no value
                [output_buffering] => 4096
                [output_encoding] => no value
                [output_handler] => no value
                [post_max_size] => 8M
                [precision] => 14
                [realpath_cache_size] => 4096K
                [realpath_cache_ttl] => 120
                [register_argc_argv] => Off
                [report_memleaks] => On
                [report_zend_debug] => On
                [request_order] => GP
                [sendmail_from] => admin@wampserver.invalid
                [sendmail_path] => no value
                [serialize_precision] => -1
                [short_open_tag] => Off
                [SMTP] => localhost
                [smtp_port] => 25
                [sys_temp_dir] => no value
                [syslog.facility] => LOG_USER
                [syslog.filter] => no-ctrl
                [syslog.ident] => php
                [track_errors] => Off
                [unserialize_callback_func] => no value
                [upload_max_filesize] => 2M
                [upload_tmp_dir] => c:/wamp/tmp
                [user_dir] => no value
                [user_ini.cache_ttl] => 300
                [user_ini.filename] => .user.ini
                [variables_order] => GPCS
                [windows.show_crt_warning] => Off
                [xmlrpc_error_number] => 0
                [xmlrpc_errors] => Off
                [zend.assertions] => 1
                [zend.detect_unicode] => On
                [zend.enable_gc] => On
                [zend.multibyte] => Off
                [zend.script_encoding] => no value
            )
    
        [Environment] => Array
            (
                [ALLUSERSPROFILE] => C:\ProgramData
                [APPDATA] => C:\WINDOWS\system32\config\systemprofile\AppData\Roaming
                [CommonProgramFiles] => C:\Program Files\Common Files
                [CommonProgramFiles(x86)] => C:\Program Files (x86)\Common Files
                [CommonProgramW6432] => C:\Program Files\Common Files
                [COMPUTERNAME] => ************************
                [ComSpec] => C:\WINDOWS\system32\cmd.exe
                [DriverData] => C:\Windows\System32\Drivers\DriverData
                [LOCALAPPDATA] => C:\WINDOWS\system32\config\systemprofile\AppData\Local
                [NUMBER_OF_PROCESSORS] => 8
                [OPENSSL_CONF] => C:\OpenSSL-Win64\bin\openssl.cfg
                [OS] => Windows_NT
                [Path] => C:\Program Files (x86)\Common Files\Oracle\Java\javapath; C:\WINDOWS\system32; C:\WINDOWS; C:\WINDOWS\System32\Wbem; C:\WINDOWS\System32\WindowsPowerShell\v1.0\; C:\WINDOWS\System32\OpenSSH\; C:\wamp\bin\php\php7.2.7; C:\ProgramData\ComposerSetup\bin; C:\Program Files\ffmpeg; C:\OpenSSL-Win64\bin; C:\wamp\bin\php\php7.3.4; C:\WINDOWS\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
                [PATHEXT] => .COM; .EXE; .BAT; .CMD; .VBS; .VBE; .JS; .JSE; .WSF; .WSH; .MSC
                [PROCESSOR_ARCHITECTURE] => AMD64
                [PROCESSOR_IDENTIFIER] => Intel64 Family 6 Model 42 Stepping 7, GenuineIntel
                [PROCESSOR_LEVEL] => 6
                [PROCESSOR_REVISION] => 2a07
                [ProgramData] => C:\ProgramData
                [ProgramFiles] => C:\Program Files
                [ProgramFiles(x86)] => C:\Program Files (x86)
                [ProgramW6432] => C:\Program Files
                [PSModulePath] => C:\Program Files\WindowsPowerShell\Modules; C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
                [PUBLIC] => C:\Users\Public
                [SystemDrive] => C:
                [SystemRoot] => C:\WINDOWS
                [TEMP] => C:\WINDOWS\TEMP
                [TMP] => C:\WINDOWS\TEMP
                [USERDOMAIN] => WORKGROUP
                [USERNAME] => SERVER-FRANCESC$
                [USERPROFILE] => C:\WINDOWS\system32\config\systemprofile
                [windir] => C:\WINDOWS
                [AP_PARENT_PID] => 15768
            )
    
        [Variable] => Array
            (
                [$_COOKIE['G_ENABLED_IDPS']] => google
                [$_COOKIE['sec_session_id']] => ************************
                [$_COOKIE['G_AUTHUSER_H']] => 0
                [$_SERVER['TZ']] => Europe/Rome
                [$_SERVER['HTTP2']] => on
                [$_SERVER['H2PUSH']] => on
                [$_SERVER['H2_PUSH']] => on
                [$_SERVER['H2_PUSHED']] => no value
                [$_SERVER['H2_PUSHED_ON']] => no value
                [$_SERVER['H2_STREAM_ID']] => 1
                [$_SERVER['H2_STREAM_TAG']] => 62-1
                [$_SERVER['HTTPS']] => on
                [$_SERVER['SSL_TLS_SNI']] => ********
                [$_SERVER['HTTP_CACHE_CONTROL']] => max-age=0
                [$_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS']] => 1
                [$_SERVER['HTTP_USER_AGENT']] => Mozilla/5.0 (Windows NT 10.0;  Win64;  x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36
                [$_SERVER['HTTP_DNT']] => 1
                [$_SERVER['HTTP_ACCEPT']] => text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange; v=b3
                [$_SERVER['HTTP_ACCEPT_ENCODING']] => gzip, deflate, br
                [$_SERVER['HTTP_ACCEPT_LANGUAGE']] => it-IT,it; q=0.9,en-US; q=0.8,en; q=0.7
                [$_SERVER['HTTP_COOKIE']] => G_ENABLED_IDPS=google;  sec_session_id=ar0pi3s1aumf0vedei77ocpvk2;  G_AUTHUSER_H=0
                [$_SERVER['HTTP_HOST']] => ************************
                [$_SERVER['PATH']] => C:\Program Files (x86)\Common Files\Oracle\Java\javapath; C:\WINDOWS\system32; C:\WINDOWS; C:\WINDOWS\System32\Wbem; C:\WINDOWS\System32\WindowsPowerShell\v1.0\; C:\WINDOWS\System32\OpenSSH\; C:\wamp\bin\php\php7.2.7; C:\ProgramData\ComposerSetup\bin; C:\Program Files\ffmpeg; C:\OpenSSL-Win64\bin; C:\wamp\bin\php\php7.3.4; C:\WINDOWS\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
                [$_SERVER['SystemRoot']] => C:\WINDOWS
                [$_SERVER['COMSPEC']] => C:\WINDOWS\system32\cmd.exe
                [$_SERVER['PATHEXT']] => .COM; .EXE; .BAT; .CMD; .VBS; .VBE; .JS; .JSE; .WSF; .WSH; .MSC
                [$_SERVER['WINDIR']] => C:\WINDOWS
                [$_SERVER['SERVER_SIGNATURE']] => no value
                [$_SERVER['SERVER_SOFTWARE']] => Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
                [$_SERVER['SERVER_NAME']] => ************************
                [$_SERVER['SERVER_ADDR']] => ********
                [$_SERVER['SERVER_PORT']] => 443
                [$_SERVER['REMOTE_ADDR']] => ************************
                [$_SERVER['DOCUMENT_ROOT']] => C:/wamp/www
                [$_SERVER['REQUEST_SCHEME']] => https
                [$_SERVER['CONTEXT_PREFIX']] => no value
                [$_SERVER['CONTEXT_DOCUMENT_ROOT']] => C:/wamp/www
                [$_SERVER['SERVER_ADMIN']] => wampserver@wampserver.invalid
                [$_SERVER['SCRIPT_FILENAME']] => C:/wamp/www/php/info/index2.php
                [$_SERVER['REMOTE_PORT']] => 62207
                [$_SERVER['GATEWAY_INTERFACE']] => CGI/1.1
                [$_SERVER['SERVER_PROTOCOL']] => HTTP/2.0
                [$_SERVER['REQUEST_METHOD']] => GET
                [$_SERVER['QUERY_STRING']] => no value
                [$_SERVER['REQUEST_URI']] => /php/info/index2.php
                [$_SERVER['SCRIPT_NAME']] => /php/info/index2.php
                [$_SERVER['PHP_SELF']] => /php/info/index2.php
                [$_SERVER['REQUEST_TIME_FLOAT']] => 1557833894.881
                [$_SERVER['REQUEST_TIME']] => 1557833894
            )
    
        [Modules] => Array
            (
                [apache2handler] => Array
                    (
                        [Apache Version] => Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
                        [Apache API Version] => 20120211
                        [Server Administrator] => wampserver@wampserver.invalid
                        [Hostname:Port] => ************************
                        [Max Requests] => Per Child: 0 - Keep Alive: on - Max Per Connection: 100
                        [Timeouts] => Connection: 60 - Keep-Alive: 5
                        [Virtual Server] => Yes
                        [Server Root] => C:/wamp/bin/apache/apache2.4.39
                        [Loaded Modules] => core mod_win32 mpm_winnt http_core mod_so mod_access_compat mod_actions mod_alias mod_allowmethods mod_asis mod_auth_basic mod_auth_digest mod_authn_core mod_authn_file mod_authz_core mod_authz_groupfile mod_authz_host mod_authz_user mod_autoindex mod_cache mod_cache_disk mod_cache_socache mod_cgi mod_deflate mod_dir mod_env mod_expires mod_file_cache mod_filter mod_http2 mod_headers mod_include mod_isapi mod_log_config mod_mime mod_negotiation mod_rewrite mod_setenvif mod_socache_shmcb mod_ssl mod_userdir mod_vhost_alias mod_php7
                        [engine] => 1
                        [last_modified] => 0
                        [xbithack] => 0
                    )
    
                [Apache Environment] => Array
                    (
                        [TZ] => Europe/Rome
                        [HTTP2] => on
                        [H2PUSH] => on
                        [H2_PUSH] => on
                        [H2_PUSHED] => no value
                        [H2_PUSHED_ON] => no value
                        [H2_STREAM_ID] => 1
                        [H2_STREAM_TAG] => 62-1
                        [HTTPS] => on
                        [SSL_TLS_SNI] => ************************
                        [HTTP_CACHE_CONTROL] => max-age=0
                        [HTTP_UPGRADE_INSECURE_REQUESTS] => 1
                        [HTTP_USER_AGENT] => Mozilla/5.0 (Windows NT 10.0;  Win64;  x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36
                        [HTTP_DNT] => 1
                        [HTTP_ACCEPT] => text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange; v=b3
                        [HTTP_ACCEPT_ENCODING] => gzip, deflate, br
                        [HTTP_ACCEPT_LANGUAGE] => it-IT,it; q=0.9,en-US; q=0.8,en; q=0.7
                        [HTTP_COOKIE] => G_ENABLED_IDPS=google;  sec_session_id=ar0pi3s1aumf0vedei77ocpvk2;  G_AUTHUSER_H=0
                        [HTTP_HOST] => ************************
                        [PATH] => C:\Program Files (x86)\Common Files\Oracle\Java\javapath; C:\WINDOWS\system32; C:\WINDOWS; C:\WINDOWS\System32\Wbem; C:\WINDOWS\System32\WindowsPowerShell\v1.0\; C:\WINDOWS\System32\OpenSSH\; C:\wamp\bin\php\php7.2.7; C:\ProgramData\ComposerSetup\bin; C:\Program Files\ffmpeg; C:\OpenSSL-Win64\bin; C:\wamp\bin\php\php7.3.4; C:\WINDOWS\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
                        [SystemRoot] => C:\WINDOWS
                        [COMSPEC] => C:\WINDOWS\system32\cmd.exe
                        [PATHEXT] => .COM; .EXE; .BAT; .CMD; .VBS; .VBE; .JS; .JSE; .WSF; .WSH; .MSC
                        [WINDIR] => C:\WINDOWS
                        [SERVER_SIGNATURE] => no value
                        [SERVER_SOFTWARE] => Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
                        [SERVER_NAME] => ************************
                        [SERVER_ADDR] => ********
                        [SERVER_PORT] => 443
                        [REMOTE_ADDR] => **.**.***.***
                        [DOCUMENT_ROOT] => C:/wamp/www
                        [REQUEST_SCHEME] => https
                        [CONTEXT_PREFIX] => no value
                        [CONTEXT_DOCUMENT_ROOT] => C:/wamp/www
                        [SERVER_ADMIN] => wampserver@wampserver.invalid
                        [SCRIPT_FILENAME] => /php/info/index2.php
                        [REMOTE_PORT] => 62207
                        [GATEWAY_INTERFACE] => CGI/1.1
                        [SERVER_PROTOCOL] => HTTP/2.0
                        [REQUEST_METHOD] => GET
                        [QUERY_STRING] => no value
                        [REQUEST_URI] => /php/info/index2.php
                        [SCRIPT_NAME] => /php/info/index2.php
                    )
    
                [HTTP Headers Information] => Array
                    (
                        [HTTP Request] => GET /php/info/index2.php HTTP/2.0
                        [Cache-Control] => max-age=0
                        [Upgrade-Insecure-Requests] => 1
                        [User-Agent] => Mozilla/5.0 (Windows NT 10.0;  Win64;  x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36
                        [Dnt] => 1
                        [Accept] => text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange; v=b3
                        [Accept-Encoding] => gzip, deflate, br
                        [Accept-Language] => it-IT,it; q=0.9,en-US; q=0.8,en; q=0.7
                        [Cookie] => G_ENABLED_IDPS=google;  sec_session_id=ar0pi3s1aumf0vedei77ocpvk2;  G_AUTHUSER_H=0
                        [Host] => ********
                        [X-Powered-By] => PHP/7.3.4
                    )
    
                [bcmath] => Array
                    (
                        [BCMath support] => enabled
                        [bcmath.scale] => 0
                    )
    
                [bz2] => Array
                    (
                        [BZip2 Support] => Enabled
                        [Stream Wrapper support] => compress.bzip2://
                        [Stream Filter support] => bzip2.decompress, bzip2.compress
                        [BZip2 Version] => 1.0.6, 6-Sept-2010
                    )
    
                [calendar] => Array
                    (
                        [Calendar support] => enabled
                    )
    
                [com_dotnet] => Array
                    (
                        [com.allow_dcom] => 0
                        [com.autoregister_casesensitive] => 1
                        [com.autoregister_typelib] => 0
                        [com.autoregister_verbose] => 0
                        [com.code_page] => no value
                        [com.typelib_file] => no value
                    )
    
                [Core] => Array
                    (
                        [PHP Version] => 7.3.4
                        [allow_url_fopen] => On
                        [allow_url_include] => Off
                        [arg_separator.input] => &amp;
                        [arg_separator.output] => &amp;
                        [auto_append_file] => no value
                        [auto_globals_jit] => Off
                        [auto_prepend_file] => no value
                        [browscap] => no value
                        [default_charset] => UTF-8
                        [default_mimetype] => text/html
                        [disable_classes] => no value
                        [disable_functions] => no value
                        [display_errors] => On
                        [display_startup_errors] => On
                        [doc_root] => no value
                        [docref_ext] => no value
                        [docref_root] => no value
                        [enable_dl] => Off
                        [enable_post_data_reading] => On
                        [error_append_string] => no value
                        [error_log] => c:/wamp/logs/php_error.log
                        [error_prepend_string] => no value
                        [error_reporting] => 32767
                        [expose_php] => On
                        [extension_dir] => c:/wamp/bin/php/php7.3.4/ext/
                        [file_uploads] => On
                        [hard_timeout] => 2
                        [highlight.comment] => #FF8000
                        [highlight.default] => #0000BB
                        [highlight.html] => #000000
                        [highlight.keyword] => #007700
                        [highlight.string] => #DD0000
                        [html_errors] => On
                        [ignore_repeated_errors] => Off
                        [ignore_repeated_source] => Off
                        [ignore_user_abort] => Off
                        [implicit_flush] => Off
                        [include_path] => .; C:\php\pear
                        [input_encoding] => no value
                        [internal_encoding] => no value
                        [log_errors] => On
                        [log_errors_max_len] => 1024
                        [mail.add_x_header] => Off
                        [mail.force_extra_parameters] => no value
                        [mail.log] => no value
                        [max_execution_time] => 0
                        [max_file_uploads] => 20
                        [max_input_nesting_level] => 64
                        [max_input_time] => 60
                        [max_input_vars] => 2500
                        [memory_limit] => 1G
                        [open_basedir] => no value
                        [output_buffering] => 4096
                        [output_encoding] => no value
                        [output_handler] => no value
                        [post_max_size] => 8M
                        [precision] => 14
                        [realpath_cache_size] => 4096K
                        [realpath_cache_ttl] => 120
                        [register_argc_argv] => Off
                        [report_memleaks] => On
                        [report_zend_debug] => On
                        [request_order] => GP
                        [sendmail_from] => admin@wampserver.invalid
                        [sendmail_path] => no value
                        [serialize_precision] => -1
                        [short_open_tag] => Off
                        [SMTP] => localhost
                        [smtp_port] => 25
                        [sys_temp_dir] => no value
                        [syslog.facility] => LOG_USER
                        [syslog.filter] => no-ctrl
                        [syslog.ident] => php
                        [track_errors] => Off
                        [unserialize_callback_func] => no value
                        [upload_max_filesize] => 2M
                        [upload_tmp_dir] => c:/wamp/tmp
                        [user_dir] => no value
                        [user_ini.cache_ttl] => 300
                        [user_ini.filename] => .user.ini
                        [variables_order] => GPCS
                        [windows.show_crt_warning] => Off
                        [xmlrpc_error_number] => 0
                        [xmlrpc_errors] => Off
                        [zend.assertions] => 1
                        [zend.detect_unicode] => On
                        [zend.enable_gc] => On
                        [zend.multibyte] => Off
                        [zend.script_encoding] => no value
                    )
    
                [ctype] => Array
                    (
                        [ctype functions] => enabled
                    )
    
                [curl] => Array
                    (
                        [cURL support] => enabled
                        [cURL Information] => 7.64.0
                        [Age] => 4
                        [AsynchDNS] => Yes
                        [CharConv] => No
                        [Debug] => No
                        [GSS-Negotiate] => No
                        [IDN] => Yes
                        [IPv6] => Yes
                        [krb4] => No
                        [Largefile] => Yes
                        [libz] => Yes
                        [NTLM] => Yes
                        [NTLMWB] => No
                        [SPNEGO] => Yes
                        [SSL] => Yes
                        [SSPI] => Yes
                        [TLS-SRP] => No
                        [HTTP2] => Yes
                        [GSSAPI] => No
                        [KERBEROS5] => Yes
                        [UNIX_SOCKETS] => No
                        [PSL] => No
                        [HTTPS_PROXY] => Yes
                        [MULTI_SSL] => No
                        [BROTLI] => No
                        [Protocols] => dict, file, ftp, ftps, gopher, http, https, imap, imaps, ldap, ldaps, pop3, pop3s, rtsp, scp, sftp, smb, smbs, smtp, smtps, telnet, tftp
                        [Host] => x86_64-pc-win32
                        [SSL Version] => OpenSSL/1.1.1b
                        [ZLib Version] => 1.2.11
                        [libSSH Version] => libssh2/1.8.2
                        [curl.cainfo] => C:\wamp\cacert.pem
                    )
    
                [date] => Array
                    (
                        [date/time support] => enabled
                        [timelib version] => 2018.01RC3
                        [&quot;Olson&quot; Timezone Database Version] => 2018.9
                        [Timezone Database] => internal
                        [Default timezone] => Europe/Rome
                        [date.default_latitude] => 31.7667
                        [date.default_longitude] => 35.2333
                        [date.sunrise_zenith] => 90.583333
                        [date.sunset_zenith] => 90.583333
                        [date.timezone] => Europe/Rome
                    )
    
                [dom] => Array
                    (
                        [DOM/XML] => enabled
                        [DOM/XML API Version] => 20031129
                        [libxml Version] => 2.9.9
                        [HTML Support] => enabled
                        [XPath Support] => enabled
                        [XPointer Support] => enabled
                        [Schema Support] => enabled
                        [RelaxNG Support] => enabled
                    )
    
                [exif] => Array
                    (
                        [EXIF Support] => enabled
                        [Supported EXIF Version] => 0220
                        [Supported filetypes] => JPEG, TIFF
                        [Multibyte decoding support using mbstring] => enabled
                        [Extended EXIF tag formats] => Canon, Casio, Fujifilm, Nikon, Olympus, Samsung, Panasonic, DJI, Sony, Pentax, Minolta, Sigma, Foveon, Kyocera, Ricoh, AGFA, Epson
                        [exif.decode_jis_intel] => JIS
                        [exif.decode_jis_motorola] => JIS
                        [exif.decode_unicode_intel] => UCS-2LE
                        [exif.decode_unicode_motorola] => UCS-2BE
                        [exif.encode_jis] => no value
                        [exif.encode_unicode] => ISO-8859-15
                    )
    
                [fileinfo] => Array
                    (
                        [fileinfo support] => enabled
                        [libmagic] => 533
                    )
    
                [filter] => Array
                    (
                        [Input Validation and Filtering] => enabled
                        [filter.default] => unsafe_raw
                        [filter.default_flags] => no value
                    )
    
                [gd] => Array
                    (
                        [GD Support] => enabled
                        [GD Version] => bundled (2.1.0 compatible)
                        [FreeType Support] => enabled
                        [FreeType Linkage] => with freetype
                        [FreeType Version] => 2.9.1
                        [GIF Read Support] => enabled
                        [GIF Create Support] => enabled
                        [JPEG Support] => enabled
                        [libJPEG Version] => 9 compatible
                        [PNG Support] => enabled
                        [libPNG Version] => 1.6.34
                        [WBMP Support] => enabled
                        [XPM Support] => enabled
                        [libXpm Version] => 30512
                        [XBM Support] => enabled
                        [WebP Support] => enabled
                        [gd.jpeg_ignore_warning] => 1
                    )
    
                [gettext] => Array
                    (
                        [GetText Support] => enabled
                    )
    
                [gmp] => Array
                    (
                        [gmp support] => enabled
                        [MPIR version] => 3.0.0
                    )
    
                [hash] => Array
                    (
                        [hash support] => enabled
                        [Hashing Engines] => md2 md4 md5 sha1 sha224 sha256 sha384 sha512/224 sha512/256 sha512 sha3-224 sha3-256 sha3-384 sha3-512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost gost-crypto adler32 crc32 crc32b fnv132 fnv1a32 fnv164 fnv1a64 joaat haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5
                        [MHASH support] => Enabled
                        [MHASH API Version] => Emulated Support
                    )
    
                [iconv] => Array
                    (
                        [iconv support] => enabled
                        [iconv implementation] => &quot; libiconv&quot;
                        [iconv library version] => 1.15
                        [iconv.input_encoding] => no value
                        [iconv.internal_encoding] => no value
                        [iconv.output_encoding] => no value
                    )
    
                [imap] => Array
                    (
                        [IMAP c-Client Version] => 2007f
                        [SSL Support] => enabled
                        [imap.enable_insecure_rsh] => Off
                    )
    
                [intl] => Array
                    (
                        [ICU version] => 63.1
                        [ICU Data version] => 63.1
                        [ICU TZData version] => 2018e
                        [ICU Unicode version] => 11.0
                        [intl.default_locale] => no value
                        [intl.error_level] => 0
                        [intl.use_exceptions] => 0
                    )
    
                [json] => Array
                    (
                        [json support] => enabled
                        [json version] => 1.7.0
                    )
    
                [ldap] => Array
                    (
                        [LDAP Support] => enabled
                        [Total Links] => 0/unlimited
                        [API Version] => 3001
                        [Vendor Name] => OpenLDAP
                        [Vendor Version] => 20445
                        [SASL Support] => Enabled
                        [ldap.max_links] => Unlimited
                    )
    
                [libxml] => Array
                    (
                        [libXML support] => active
                        [libXML Compiled Version] => 2.9.9
                        [libXML Loaded Version] => 20909
                        [libXML streams] => enabled
                    )
    
                [mbstring] => Array
                    (
                        [Multibyte Support] => enabled
                        [Multibyte string engine] => libmbfl
                        [HTTP input encoding translation] => disabled
                        [libmbfl version] => 1.3.2
                        [oniguruma version] => 6.9.0
                        [Multibyte (japanese) regex support] => enabled
                        [Multibyte regex (oniguruma) version] => 6.9.0
                        [mbstring.detect_order] => no value
                        [mbstring.encoding_translation] => Off
                        [mbstring.func_overload] => 0
                        [mbstring.http_input] => no value
                        [mbstring.http_output] => no value
                        [mbstring.http_output_conv_mimetypes] => ^(text/|application/xhtml\+xml)
                        [mbstring.internal_encoding] => no value
                        [mbstring.language] => neutral
                        [mbstring.strict_detection] => Off
                        [mbstring.substitute_character] => no value
                    )
    
                [mysqli] => Array
                    (
                        [Client API library version] => mysqlnd 5.0.12-dev - 20150407 - $Id: ******** $
                        [Active Persistent Links] => 0
                        [Inactive Persistent Links] => 0
                        [Active Links] => 0
                        [mysqli.allow_local_infile] => Off
                        [mysqli.allow_persistent] => On
                        [mysqli.default_host] => no value
                        [mysqli.default_port] => 3306
                        [mysqli.default_pw] => no value
                        [mysqli.default_socket] => no value
                        [mysqli.default_user] => no value
                        [mysqli.max_links] => Unlimited
                        [mysqli.max_persistent] => Unlimited
                        [mysqli.reconnect] => Off
                        [mysqli.rollback_on_cached_plink] => Off
                    )
    
                [mysqlnd] => Array
                    (
                        [Version] => mysqlnd 5.0.12-dev - 20150407 - $Id: ******** $
                        [Compression] => supported
                        [core SSL] => supported
                        [extended SSL] => not supported
                        [Command buffer size] => 4096
                        [Read buffer size] => 32768
                        [Read timeout] => 86400
                        [Collecting statistics] => Yes
                        [Collecting memory statistics] => Yes
                        [Tracing] => n/a
                        [Loaded plugins] => mysqlnd,debug_trace,auth_plugin_mysql_native_password,auth_plugin_mysql_clear_password
                        [API Extensions] => mysqli,pdo_mysql
                        [bytes_sent] => 35726403
                        [bytes_received] => 83642540
                        [packets_sent] => 400736
                        [packets_received] => 1254774
                        [protocol_overhead_in] => 5019096
                        [protocol_overhead_out] => 1602944
                        [bytes_received_ok_packet] => 0
                        [bytes_received_eof_packet] => 0
                        [bytes_received_rset_header_packet] => 430713
                        [bytes_received_rset_field_meta_packet] => 0
                        [bytes_received_rset_row_packet] => 856976
                        [bytes_received_prepare_response_packet] => 35830963
                        [bytes_received_change_user_packet] => 41992400
                        [packets_sent_command] => 152141
                        [packets_received_ok] => 0
                        [packets_received_eof] => 0
                        [packets_received_rset_header] => 47857
                        [packets_received_rset_field_meta] => 0
                        [packets_received_rset_row] => 103914
                        [packets_received_prepare_response] => 621859
                        [packets_received_change_user] => 384690
                        [result_set_queries] => 47857
                        [non_result_set_queries] => 56057
                        [no_index_used] => 47831
                        [bad_index_used] => 0
                        [slow_queries] => 0
                        [buffered_sets] => 47857
                        [unbuffered_sets] => 0
                        [ps_buffered_sets] => 0
                        [ps_unbuffered_sets] => 0
                        [flushed_normal_sets] => 0
                        [flushed_ps_sets] => 0
                        [ps_prepared_never_executed] => 0
                        [ps_prepared_once_executed] => 0
                        [rows_fetched_from_server_normal] => 336833
                        [rows_fetched_from_server_ps] => 0
                        [rows_buffered_from_client_normal] => 336833
                        [rows_buffered_from_client_ps] => 0
                        [rows_fetched_from_client_normal_buffered] => 336833
                        [rows_fetched_from_client_normal_unbuffered] => 0
                        [rows_fetched_from_client_ps_buffered] => 0
                        [rows_fetched_from_client_ps_unbuffered] => 0
                        [rows_fetched_from_client_ps_cursor] => 0
                        [rows_affected_normal] => 790
                        [rows_affected_ps] => 0
                        [rows_skipped_normal] => 336833
                        [rows_skipped_ps] => 0
                        [copy_on_write_saved] => 0
                        [copy_on_write_performed] => 0
                        [command_buffer_too_small] => 0
                        [connect_success] => 48227
                        [connect_failure] => 0
                        [connection_reused] => 0
                        [reconnect] => 0
                        [pconnect_success] => 0
                        [active_connections] => 18446744073709503389
                        [active_persistent_connections] => 0
                        [explicit_close] => 48227
                        [implicit_close] => 0
                        [disconnect_close] => 0
                        [in_middle_of_command_close] => 0
                        [explicit_free_result] => 47857
                        [implicit_free_result] => 0
                        [explicit_stmt_close] => 0
                        [implicit_stmt_close] => 0
                        [mem_emalloc_count] => 337434
                        [mem_emalloc_amount] => 1027605009
                        [mem_ecalloc_count] => 241135
                        [mem_ecalloc_amount] => 96454000
                        [mem_erealloc_count] => 371
                        [mem_erealloc_amount] => 407131504
                        [mem_efree_count] => 1012638
                        [mem_efree_amount] => 1135051195
                        [mem_malloc_count] => 0
                        [mem_malloc_amount] => 0
                        [mem_calloc_count] => 0
                        [mem_calloc_amount] => 0
                        [mem_realloc_count] => 0
                        [mem_realloc_amount] => 0
                        [mem_free_count] => 0
                        [mem_free_amount] => 0
                        [mem_estrndup_count] => 241161
                        [mem_strndup_count] => 0
                        [mem_estrdup_count] => 192908
                        [mem_strdup_count] => 0
                        [mem_edupl_count] => 0
                        [mem_dupl_count] => 0
                        [proto_text_fetched_null] => 0
                        [proto_text_fetched_bit] => 0
                        [proto_text_fetched_tinyint] => 0
                        [proto_text_fetched_short] => 0
                        [proto_text_fetched_int24] => 0
                        [proto_text_fetched_int] => 246471
                        [proto_text_fetched_bigint] => 2
                        [proto_text_fetched_decimal] => 0
                        [proto_text_fetched_float] => 655545
                        [proto_text_fetched_double] => 156245
                        [proto_text_fetched_date] => 0
                        [proto_text_fetched_year] => 0
                        [proto_text_fetched_time] => 0
                        [proto_text_fetched_datetime] => 233753
                        [proto_text_fetched_timestamp] => 0
                        [proto_text_fetched_string] => 389509
                        [proto_text_fetched_blob] => 0
                        [proto_text_fetched_enum] => 821709
                        [proto_text_fetched_set] => 0
                        [proto_text_fetched_geometry] => 0
                        [proto_text_fetched_other] => 0
                        [proto_binary_fetched_null] => 0
                        [proto_binary_fetched_bit] => 0
                        [proto_binary_fetched_tinyint] => 0
                        [proto_binary_fetched_short] => 0
                        [proto_binary_fetched_int24] => 0
                        [proto_binary_fetched_int] => 0
                        [proto_binary_fetched_bigint] => 0
                        [proto_binary_fetched_decimal] => 0
                        [proto_binary_fetched_float] => 0
                        [proto_binary_fetched_double] => 0
                        [proto_binary_fetched_date] => 0
                        [proto_binary_fetched_year] => 0
                        [proto_binary_fetched_time] => 0
                        [proto_binary_fetched_datetime] => 0
                        [proto_binary_fetched_timestamp] => 0
                        [proto_binary_fetched_string] => 0
                        [proto_binary_fetched_json] => 0
                        [proto_binary_fetched_blob] => 0
                        [proto_binary_fetched_enum] => 0
                        [proto_binary_fetched_set] => 0
                        [proto_binary_fetched_geometry] => 0
                        [proto_binary_fetched_other] => 0
                        [init_command_executed_count] => 0
                        [init_command_failed_count] => 0
                        [com_quit] => 48227
                        [com_init_db] => 0
                        [com_query] => 103914
                        [com_field_list] => 0
                        [com_create_db] => 0
                        [com_drop_db] => 0
                        [com_refresh] => 0
                        [com_shutdown] => 0
                        [com_statistics] => 0
                        [com_process_info] => 0
                        [com_connect] => 0
                        [com_process_kill] => 0
                        [com_debug] => 0
                        [com_ping] => 0
                        [com_time] => 0
                        [com_delayed_insert] => 0
                        [com_change_user] => 0
                        [com_binlog_dump] => 0
                        [com_table_dump] => 0
                        [com_connect_out] => 0
                        [com_register_slave] => 0
                        [com_stmt_prepare] => 0
                        [com_stmt_execute] => 0
                        [com_stmt_send_long_data] => 0
                        [com_stmt_close] => 0
                        [com_stmt_reset] => 0
                        [com_stmt_set_option] => 0
                        [com_stmt_fetch] => 0
                        [com_deamon] => 0
                        [bytes_received_real_data_normal] => 37902647
                        [bytes_received_real_data_ps] => 0
                    )
    
                [odbc] => Array
                    (
                        [Active Persistent Links] => 0
                        [Active Links] => 0
                        [ODBC library] => Win32
                        [ODBCVER] => 0x0350
                        [odbc.allow_persistent] => On
                        [odbc.check_persistent] => On
                        [odbc.default_cursortype] => Static cursor
                        [odbc.default_db] => no value
                        [odbc.default_pw] => no value
                        [odbc.default_user] => no value
                        [odbc.defaultbinmode] => return as is
                        [odbc.defaultlrl] => return up to 4096 bytes
                        [odbc.max_links] => Unlimited
                        [odbc.max_persistent] => Unlimited
                    )
    
                [openssl] => Array
                    (
                        [OpenSSL support] => enabled
                        [OpenSSL Library Version] => OpenSSL 1.1.1b  26 Feb 2019
                        [OpenSSL Header Version] => OpenSSL 1.1.1b  26 Feb 2019
                        [Openssl default config] => C:\OpenSSL-Win64\bin\openssl.cfg
                        [openssl.cafile] => no value
                        [openssl.capath] => no value
                    )
    
                [pcre] => Array
                    (
                        [PCRE (Perl Compatible Regular Expressions) Support] => enabled
                        [PCRE Library Version] => 10.32 2018-09-10
                        [PCRE Unicode Version] => 11.0.0
                        [PCRE JIT Support] => enabled
                        [PCRE JIT Target] => x86 64bit (little endian + unaligned)
                        [pcre.backtrack_limit] => 1000000
                        [pcre.jit] => 1
                        [pcre.recursion_limit] => 100000
                    )
    
                [PDO] => Array
                    (
                        [PDO drivers] => mysql, sqlite
                    )
    
                [pdo_mysql] => Array
                    (
                        [Client API version] => mysqlnd 5.0.12-dev - 20150407 - $Id: ******** $
                    )
    
                [pdo_sqlite] => Array
                    (
                        [SQLite Library] => 3.24.0
                    )
    
                [Phar] => Array
                    (
                        [Phar API version] => 1.1.1
                        [Phar-based phar archives] => enabled
                        [Tar-based phar archives] => enabled
                        [ZIP-based phar archives] => enabled
                        [gzip compression] => enabled
                        [bzip2 compression] => enabled
                        [OpenSSL support] => enabled
                        [phar.cache_list] => no value
                        [phar.readonly] => On
                        [phar.require_hash] => On
                    )
    
                [readline] => Array
                    (
                        [Readline library] => WinEditLine
                        [cli.pager] => no value
                        [cli.prompt] => \b&nbsp; \&gt; &nbsp;
                    )
    
                [Reflection] => Array
                    (
                        [Reflection] => enabled
                    )
    
                [session] => Array
                    (
                        [Session Support] => enabled
                        [Registered save handlers] => files user
                        [Registered serializer handlers] => php_serialize php php_binary wddx
                        [session.auto_start] => Off
                        [session.cache_expire] => 180
                        [session.cache_limiter] => nocache
                        [session.cookie_domain] => no value
                        [session.cookie_httponly] => no value
                        [session.cookie_lifetime] => 0
                        [session.cookie_path] => /
                        [session.cookie_samesite] => no value
                        [session.cookie_secure] => 0
                        [session.gc_divisor] => 1000
                        [session.gc_maxlifetime] => 1440
                        [session.gc_probability] => 1
                        [session.lazy_write] => On
                        [session.name] => PHPSESSID
                        [session.referer_check] => no value
                        [session.save_handler] => files
                        [session.save_path] => c:/wamp/tmp
                        [session.serialize_handler] => php
                        [session.sid_bits_per_character] => 5
                        [session.sid_length] => 26
                        [session.upload_progress.cleanup] => On
                        [session.upload_progress.enabled] => On
                        [session.upload_progress.freq] => 1%
                        [session.upload_progress.min_freq] => 1
                        [session.upload_progress.name] => PHP_SESSION_UPLOAD_PROGRESS
                        [session.upload_progress.prefix] => upload_progress_
                        [session.use_cookies] => 1
                        [session.use_only_cookies] => 1
                        [session.use_strict_mode] => 0
                        [session.use_trans_sid] => 0
                    )
    
                [SimpleXML] => Array
                    (
                        [SimpleXML support] => enabled
                        [Schema support] => enabled
                    )
    
                [soap] => Array
                    (
                        [Soap Client] => enabled
                        [Soap Server] => enabled
                        [soap.wsdl_cache] => 1
                        [soap.wsdl_cache_dir] => c:/wamp/tmp
                        [soap.wsdl_cache_enabled] => 1
                        [soap.wsdl_cache_limit] => 5
                        [soap.wsdl_cache_ttl] => 86400
                    )
    
                [sockets] => Array
                    (
                        [Sockets Support] => enabled
                    )
    
                [SPL] => Array
                    (
                        [Interfaces] => OuterIterator, RecursiveIterator, SeekableIterator, SplObserver, SplSubject
                        [Classes] => AppendIterator, ArrayIterator, ArrayObject, BadFunctionCallException, BadMethodCallException, CachingIterator, CallbackFilterIterator, DirectoryIterator, DomainException, EmptyIterator, FilesystemIterator, FilterIterator, GlobIterator, InfiniteIterator, InvalidArgumentException, IteratorIterator, LengthException, LimitIterator, LogicException, MultipleIterator, NoRewindIterator, OutOfBoundsException, OutOfRangeException, OverflowException, ParentIterator, RangeException, RecursiveArrayIterator, RecursiveCachingIterator, RecursiveCallbackFilterIterator, RecursiveDirectoryIterator, RecursiveFilterIterator, RecursiveIteratorIterator, RecursiveRegexIterator, RecursiveTreeIterator, RegexIterator, RuntimeException, SplDoublyLinkedList, SplFileInfo, SplFileObject, SplFixedArray, SplHeap, SplMinHeap, SplMaxHeap, SplObjectStorage, SplPriorityQueue, SplQueue, SplStack, SplTempFileObject, UnderflowException, UnexpectedValueException
                    )
    
                [sqlite3] => Array
                    (
                        [SQLite Library] => 3.24.0
                        [sqlite3.extension_dir] => no value
                    )
    
                [standard] => Array
                    (
                        [Dynamic Library Support] => enabled
                        [Internal Sendmail Support for Windows] => enabled
                        [assert.active] => 1
                        [assert.bail] => 0
                        [assert.callback] => no value
                        [assert.exception] => 0
                        [assert.quiet_eval] => 0
                        [assert.warning] => 1
                        [auto_detect_line_endings] => 0
                        [default_socket_timeout] => 60
                        [from] => no value
                        [session.trans_sid_hosts] => no value
                        [session.trans_sid_tags] => a=href,area=href,frame=src,form=
                        [url_rewriter.hosts] => no value
                        [url_rewriter.tags] => form=
                        [user_agent] => no value
                    )
    
                [tokenizer] => Array
                    (
                        [Tokenizer Support] => enabled
                    )
    
                [wddx] => Array
                    (
                        [WDDX Session Serializer] => enabled
                    )
    
                [xdebug] => Array
                    (
                        [Version] => 2.7.1
                        [IDE Key] => SERVER-FRANCESC$
                        [xdebug.auto_trace] => Off
                        [xdebug.cli_color] => 0
                        [xdebug.collect_assignments] => Off
                        [xdebug.collect_includes] => On
                        [xdebug.collect_params] => 0
                        [xdebug.collect_return] => Off
                        [xdebug.collect_vars] => Off
                        [xdebug.coverage_enable] => On
                        [xdebug.default_enable] => On
                        [xdebug.dump.COOKIE] => no value
                        [xdebug.dump.ENV] => no value
                        [xdebug.dump.FILES] => no value
                        [xdebug.dump.GET] => no value
                        [xdebug.dump.POST] => no value
                        [xdebug.dump.REQUEST] => no value
                        [xdebug.dump.SERVER] => no value
                        [xdebug.dump.SESSION] => no value
                        [xdebug.dump_globals] => On
                        [xdebug.dump_once] => On
                        [xdebug.dump_undefined] => Off
                        [xdebug.extended_info] => On
                        [xdebug.file_link_format] => no value
                        [xdebug.filename_format] => no value
                        [xdebug.force_display_errors] => Off
                        [xdebug.force_error_reporting] => 0
                        [xdebug.gc_stats_enable] => Off
                        [xdebug.gc_stats_output_dir] => C:\Windows\Temp
                        [xdebug.gc_stats_output_name] => gcstats.%p
                        [xdebug.halt_level] => 0
                        [xdebug.idekey] => no value
                        [xdebug.max_nesting_level] => 256
                        [xdebug.max_stack_frames] => -1
                        [xdebug.overload_var_dump] => 2
                        [xdebug.profiler_aggregate] => Off
                        [xdebug.profiler_append] => Off
                        [xdebug.profiler_enable] => Off
                        [xdebug.profiler_enable_trigger] => Off
                        [xdebug.profiler_enable_trigger_value] => no value
                        [xdebug.profiler_output_dir] => c:/wamp/tmp
                        [xdebug.profiler_output_name] => cachegrind.out.%t.%p
                        [xdebug.remote_addr_header] => no value
                        [xdebug.remote_autostart] => Off
                        [xdebug.remote_connect_back] => Off
                        [xdebug.remote_cookie_expire_time] => 3600
                        [xdebug.remote_enable] => Off
                        [xdebug.remote_handler] => dbgp
                        [xdebug.remote_host] => localhost
                        [xdebug.remote_log] => no value
                        [xdebug.remote_mode] => req
                        [xdebug.remote_port] => 9000
                        [xdebug.remote_timeout] => 200
                        [xdebug.scream] => Off
                        [xdebug.show_error_trace] => Off
                        [xdebug.show_exception_trace] => Off
                        [xdebug.show_local_vars] => Off
                        [xdebug.show_mem_delta] => Off
                        [xdebug.trace_enable_trigger] => Off
                        [xdebug.trace_enable_trigger_value] => no value
                        [xdebug.trace_format] => 0
                        [xdebug.trace_options] => 0
                        [xdebug.trace_output_dir] => C:\Windows\Temp
                        [xdebug.trace_output_name] => trace.%c
                        [xdebug.var_display_max_children] => 128
                        [xdebug.var_display_max_data] => 512
                        [xdebug.var_display_max_depth] => 3
                    )
    
                [xml] => Array
                    (
                        [XML Support] => active
                        [XML Namespace Support] => active
                        [libxml2 Version] => 2.9.9
                    )
    
                [xmlreader] => Array
                    (
                        [XMLReader] => enabled
                    )
    
                [xmlrpc] => Array
                    (
                        [core library version] => xmlrpc-epi v. 0.51
                        [author] => Dan Libby
                        [homepage] => http://xmlrpc-epi.sourceforge.net
                        [open sourced by] => Epinions.com
                    )
    
                [xmlwriter] => Array
                    (
                        [XMLWriter] => enabled
                    )
    
                [xsl] => Array
                    (
                        [XSL] => enabled
                        [libxslt Version] => 1.1.32
                        [libxslt compiled against libxml Version] => 2.9.7
                        [EXSLT] => enabled
                        [libexslt Version] => 0.8.20
                    )
    
                [Zend OPcache] => Array
                    (
                        [Opcode Caching] => Up and Running
                        [Optimization] => Enabled
                        [SHM Cache] => Enabled
                        [File Cache] => Disabled
                        [Startup] => OK
                        [Shared memory model] => win32
                        [Cache hits] => 730930
                        [Cache misses] => 267
                        [Used memory] => 12460888
                        [Free memory] => 119170352
                        [Wasted memory] => 2586488
                        [Interned Strings Used memory] => 959176
                        [Interned Strings Free memory] => 5331832
                        [Cached scripts] => 106
                        [Cached keys] => 303
                        [Max keys] => 16229
                        [OOM restarts] => 0
                        [Hash keys restarts] => 0
                        [Manual restarts] => 0
                        [opcache.blacklist_filename] => no value
                        [opcache.consistency_checks] => 0
                        [opcache.dups_fix] => Off
                        [opcache.enable] => On
                        [opcache.enable_cli] => Off
                        [opcache.enable_file_override] => Off
                        [opcache.error_log] => no value
                        [opcache.file_cache] => no value
                        [opcache.file_cache_consistency_checks] => 1
                        [opcache.file_cache_fallback] => 1
                        [opcache.file_cache_only] => 0
                        [opcache.file_update_protection] => 2
                        [opcache.force_restart_timeout] => 180
                        [opcache.interned_strings_buffer] => 8
                        [opcache.log_verbosity_level] => 1
                        [opcache.max_accelerated_files] => 10000
                        [opcache.max_file_size] => 0
                        [opcache.max_wasted_percentage] => 5
                        [opcache.memory_consumption] => 128
                        [opcache.mmap_base] => no value
                        [opcache.opt_debug_level] => 0
                        [opcache.optimization_level] => 0x7FFEBFFF
                        [opcache.preferred_memory_model] => no value
                        [opcache.protect_memory] => 0
                        [opcache.restrict_api] => no value
                        [opcache.revalidate_freq] => 2
                        [opcache.revalidate_path] => Off
                        [opcache.save_comments] => 1
                        [opcache.use_cwd] => On
                        [opcache.validate_permission] => Off
                        [opcache.validate_timestamps] => On
                    )
    
                [zip] => Array
                    (
                        [Zip] => enabled
                        [Zip version] => 1.15.4
                        [Libzip version] => 1.4.0
                    )
    
                [zlib] => Array
                    (
                        [Stream Wrapper] => compress.zlib://
                        [Stream Filter] => zlib.inflate, zlib.deflate
                        [Compiled Version] => 1.2.11
                        [Linked Version] => 1.2.11
                        [zlib.output_compression] => On
                        [zlib.output_compression_level] => -1
                        [zlib.output_handler] => no value
                    )
    
            )
    
        [Credits] => Array
            (
                [Zend Scripting Language Engine] => Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Marcus Boerger, Dmitry Stogov, Xinchen Hui, Nikita Popov
                [Extension Module API] => Andi Gutmans, Zeev Suraski, Andrei Zmievski
                [UNIX Build and Modularization] => Stig Bakken, Sascha Schumann, Jani Taskinen
                [Windows Support] => Shane Caraveo, Zeev Suraski, Wez Furlong, Pierre-Alain Joye, Anatol Belski, Kalle Sommer Nielsen
                [Server API (SAPI) Abstraction Layer] => Andi Gutmans, Shane Caraveo, Zeev Suraski
                [Streams Abstraction Layer] => Wez Furlong, Sara Golemon
                [PHP Data Objects Layer] => Wez Furlong, Marcus Boerger, Sterling Hughes, George Schlossnagle, Ilia Alshanetsky
                [Output Handler] => Zeev Suraski, Thies C. Arntzen, Marcus Boerger, Michael Wallner
                [Consistent 64 bit support] => Anthony Ferrara, Anatol Belski
                [Apache 2.0 Handler] => Ian Holsman, Justin Erenkrantz (based on Apache 2.0 Filter code)
                [CGI / FastCGI] => Rasmus Lerdorf, Stig Bakken, Shane Caraveo, Dmitry Stogov
                [CLI] => Edin Kadribasic, Marcus Boerger, Johannes Schlueter, Moriyoshi Koizumi, Xinchen Hui
                [Embed] => Edin Kadribasic
                [FastCGI Process Manager] => Andrei Nigmatulin, dreamcat4, Antony Dovgal, Jerome Loyet
                [litespeed] => George Wang
                [phpdbg] => Felipe Pena, Joe Watkins, Bob Weinand
                [BC Math] => Andi Gutmans
                [Bzip2] => Sterling Hughes
                [Calendar] => Shane Caraveo, Colin Viebrock, Hartmut Holzgraefe, Wez Furlong
                [COM and .Net] => Wez Furlong
                [ctype] => Hartmut Holzgraefe
                [cURL] => Sterling Hughes
                [Date/Time Support] => Derick Rethans
                [DB-LIB (MS SQL, Sybase)] => Wez Furlong, Frank M. Kromann, Adam Baratz
                [DBA] => Sascha Schumann, Marcus Boerger
                [DOM] => Christian Stocker, Rob Richards, Marcus Boerger
                [enchant] => Pierre-Alain Joye, Ilia Alshanetsky
                [EXIF] => Rasmus Lerdorf, Marcus Boerger
                [fileinfo] => Ilia Alshanetsky, Pierre Alain Joye, Scott MacVicar, Derick Rethans, Anatol Belski
                [Firebird driver for PDO] => Ard Biesheuvel
                [FTP] => Stefan Esser, Andrew Skalski
                [GD imaging] => Rasmus Lerdorf, Stig Bakken, Jim Winstead, Jouni Ahto, Ilia Alshanetsky, Pierre-Alain Joye, Marcus Boerger
                [GetText] => Alex Plotnick
                [GNU GMP support] => Stanislav Malyshev
                [Iconv] => Rui Hirokawa, Stig Bakken, Moriyoshi Koizumi
                [IMAP] => Rex Logan, Mark Musone, Brian Wang, Kaj-Michael Lang, Antoni Pamies Olive, Rasmus Lerdorf, Andrew Skalski, Chuck Hagenbuch, Daniel R Kalowsky
                [Input Filter] => Rasmus Lerdorf, Derick Rethans, Pierre-Alain Joye, Ilia Alshanetsky
                [InterBase] => Jouni Ahto, Andrew Avdeev, Ard Biesheuvel
                [Internationalization] => Ed Batutis, Vladimir Iordanov, Dmitry Lakhtyuk, Stanislav Malyshev, Vadim Savchuk, Kirti Velankar
                [JSON] => Jakub Zelenka, Omar Kilani, Scott MacVicar
                [LDAP] => Amitay Isaacs, Eric Warnke, Rasmus Lerdorf, Gerrit Thomson, Stig Venaas
                [LIBXML] => Christian Stocker, Rob Richards, Marcus Boerger, Wez Furlong, Shane Caraveo
                [Multibyte String Functions] => Tsukada Takuya, Rui Hirokawa
                [MySQL driver for PDO] => George Schlossnagle, Wez Furlong, Ilia Alshanetsky, Johannes Schlueter
                [MySQLi] => Zak Greant, Georg Richter, Andrey Hristov, Ulf Wendel
                [MySQLnd] => Andrey Hristov, Ulf Wendel, Georg Richter, Johannes Schlüter
                [OCI8] => Stig Bakken, Thies C. Arntzen, Andy Sautins, David Benson, Maxim Maletsky, Harald Radi, Antony Dovgal, Andi Gutmans, Wez Furlong, Christopher Jones, Oracle Corporation
                [ODBC driver for PDO] => Wez Furlong
                [ODBC] => Stig Bakken, Andreas Karajannis, Frank M. Kromann, Daniel R. Kalowsky
                [Opcache] => Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Dmitry Stogov, Xinchen Hui
                [OpenSSL] => Stig Venaas, Wez Furlong, Sascha Kettler, Scott MacVicar
                [Oracle (OCI) driver for PDO] => Wez Furlong
                [pcntl] => Jason Greene, Arnaud Le Blanc
                [Perl Compatible Regexps] => Andrei Zmievski
                [PHP Archive] => Gregory Beaver, Marcus Boerger
                [PHP Data Objects] => Wez Furlong, Marcus Boerger, Sterling Hughes, George Schlossnagle, Ilia Alshanetsky
                [PHP hash] => Sara Golemon, Rasmus Lerdorf, Stefan Esser, Michael Wallner, Scott MacVicar
                [Posix] => Kristian Koehntopp
                [PostgreSQL driver for PDO] => Edin Kadribasic, Ilia Alshanetsky
                [PostgreSQL] => Jouni Ahto, Zeev Suraski, Yasuo Ohgaki, Chris Kings-Lynne
                [Pspell] => Vlad Krupin
                [Readline] => Thies C. Arntzen
                [Recode] => Kristian Koehntopp
                [Reflection] => Marcus Boerger, Timm Friebe, George Schlossnagle, Andrei Zmievski, Johannes Schlueter
                [Sessions] => Sascha Schumann, Andrei Zmievski
                [Shared Memory Operations] => Slava Poliakov, Ilia Alshanetsky
                [SimpleXML] => Sterling Hughes, Marcus Boerger, Rob Richards
                [SNMP] => Rasmus Lerdorf, Harrie Hazewinkel, Mike Jackson, Steven Lawrance, Johann Hanne, Boris Lytochkin
                [SOAP] => Brad Lafountain, Shane Caraveo, Dmitry Stogov
                [Sockets] => Chris Vandomelen, Sterling Hughes, Daniel Beulshausen, Jason Greene
                [Sodium] => Frank Denis
                [SPL] => Marcus Boerger, Etienne Kneuss
                [SQLite 3.x driver for PDO] => Wez Furlong
                [SQLite3] => Scott MacVicar, Ilia Alshanetsky, Brad Dewar
                [System V Message based IPC] => Wez Furlong
                [System V Semaphores] => Tom May
                [System V Shared Memory] => Christian Cartus
                [tidy] => John Coggeshall, Ilia Alshanetsky
                [tokenizer] => Andrei Zmievski, Johannes Schlueter
                [WDDX] => Andrei Zmievski
                [XML] => Stig Bakken, Thies C. Arntzen, Sterling Hughes
                [XMLReader] => Rob Richards
                [xmlrpc] => Dan Libby
                [XMLWriter] => Rob Richards, Pierre-Alain Joye
                [XSL] => Christian Stocker, Rob Richards
                [Zip] => Pierre-Alain Joye, Remi Collet
                [Zlib] => Rasmus Lerdorf, Stefan Roehrich, Zeev Suraski, Jade Nicoletti, Michael Wallner
                [Authors] => Mehdi Achour, Friedhelm Betz, Antony Dovgal, Nuno Lopes, Hannes Magnusson, Philip Olson, Georg Richter, Damien Seguy, Jakub Vrana, Adam Harvey
                [Editor] => Peter Cowburn
                [User Note Maintainers] => Daniel P. Brown, Thiago Henrique Pojda
                [Other Contributors] => Previously active authors, editors and other contributors are listed in the manual.
                [PHP Websites Team] => Rasmus Lerdorf, Hannes Magnusson, Philip Olson, Lukas Kahwe Smith, Pierre-Alain Joye, Kalle Sommer Nielsen, Peter Cowburn, Adam Harvey, Ferenc Kovacs, Levi Morrison
                [Event Maintainers] => Damien Seguy, Daniel P. Brown
                [Network Infrastructure] => Daniel P. Brown
                [Windows Infrastructure] => Alex Schoenmaker
            )
    
        [License] => This program is free software; you can redistribute it and/or modify it under the terms of the PHP License as published by the PHP Group and included in the distribution in the file:  LICENSE. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.. If you did not receive a copy of the PHP license, or have any questions about PHP licensing, please contact license@php.net.
    )
    ```
