# SPDX-FileCopyrightText: 2002 Michel Arboi
# SPDX-FileCopyrightText: New code/functions since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Global vars to avoid that we're repeatedly asking redis for something we already know.
global_var __http_func_user_agent, __http_is_cgi_scan_disabled, __http_is_kb_caching_disabled, __http_ua_include_oid;

# Enables debugging output for a few functions below.
global_var _http_debug;
_http_debug = FALSE;

# Global var passed to a few functions below
global_var optimize_test_enabled;
optimize_test_enabled = get_preference( "optimize_test" );

# Global vars to avoid that we're repeatedly asking redis for something we already know.
global_var _http_is_broken_array, _http_has_generic_xss_array;

# nb: key is the host+port or NULL (if not previously checked), value TRUE/FALSE if broken or not
_http_is_broken_array = make_array();

# nb: key is the host+port or NULL (if not previously checked), value TRUE/FALSE if it has a generic XSS or not
_http_has_generic_xss_array = make_array();

# @brief Returns a HTTP User Agent string which can be used by VTs within the
#        User-Agent: header of HTTP requests.
#
# @param vt_string This is a string which is initially used to build the default UA string for the
#                  case where the "http/user-agent" KB key is empty initially.
# @param dont_add_oid If set to TRUE don't add the OID of the calling VT to the User-Agent string
#                     even if the @ref http_ua_include_oid relevant scan config option is set.
#
# @return A string containing a HTTP user agent.
#
function http_get_user_agent( vt_string, dont_add_oid ) {

  local_var vt_string, dont_add_oid;
  local_var ua_vt_string, vendor, default, ua;
  # nb: __http_func_user_agent is global var

  if( vt_string )
    ua_vt_string = vt_string;
  else
    ua_vt_string = "OpenVAS-VT";

  # nb: Only used if the function is called by a VT running via openvas-nasl
  # and if global_settings.nasl wasn't called before that VT.
  if( defined_func( "vendor_version" ) )
    vendor = vendor_version();
  else
    vendor = NULL;

  if( ! isnull( vendor ) && vendor != "" )
    default = "Mozilla/5.0 [en] (X11, U; " + vendor + ")";
  else if( OPENVAS_VERSION )
    default = "Mozilla/5.0 [en] (X11, U; " + ua_vt_string + " " + OPENVAS_VERSION + ")";
  else
    default = "Mozilla/5.0 [en] (X11, U; " + ua_vt_string + ")";

  if( ! isnull( __http_func_user_agent ) ) {
    ua = string( __http_func_user_agent );
  } else {
    ua = get_kb_item( "http/user-agent" );
    if( ! isnull( ua ) ) {
      __http_func_user_agent = string( ua );
    } else {
      __http_func_user_agent = default;
      ua = default;
    }
  }

  # nb: See description of the variable for the purpose
  if( http_ua_include_oid() && ! dont_add_oid )
    ua = ereg_replace( string:ua, pattern:"(.+)$", replace:"\1 (OID:" + get_script_oid() + ")" );

  return ua;
}

# @brief Split the passed HTTP header into an array containing the header names as an array
#        key and the header values as the array value.
#
# @param h The full HTTP header to split into an array.
#
# @return An array containing the split header or NULL if no header was passed or contained invalid data.
#
function http_headers_split( h ) {

  local_var h;
  local_var end, array, _item, subarray, ret;

  if( ! h )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#h#-#http_headers_split" );

  end = strstr( h, '\r\n\r\n' );
  if( end )
    h -= end;

  array = split( h, keep:FALSE );
  foreach _item( array ) {
    subarray = split( _item, sep:':', keep:FALSE );
    ret[tolower( subarray[0] )] = ereg_replace( pattern:"^ *", replace:"", string:subarray[1] );
  }

  return ret;
}

# @brief Converts a single hex char, e.g. '0' or 'a' into the integer representation of this
#        char. The function is used e.g. for chunk-decoding.
#
# @param num The hex char to convert.
#
# @return An integer representation of the passed char.
#
function __hex_value( num ) {

  local_var num;

  if( num == "a") return( 10 );
  if( num == "b") return( 11 );
  if( num == "c") return( 12 );
  if( num == "d") return( 13 );
  if( num == "e") return( 14 );
  if( num == "f") return( 15 );
  return( int( num ) );
}

# @brief Converts a passed hex string into the decimal representation of the string. Examples:
#        xvalue: 0x0a0b or 0x0A0B -> Return 2571
#        xvalue: 0x0a or 0x0A -> Return 10
#
# @param xvalue The hex string to convert.
#
# @return A decimal representation of the passed hex string or 0 if no string was passed.
#
function hex2dec( xvalue ) {

  local_var xvalue;
  local_var l, ret, m, i, n;

  if( ! xvalue ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#xvalue#-#hex2dec" );
    return( 0 );
  }

  xvalue = tolower( xvalue );
  if( '\r\n' >< xvalue ) {
    l = strlen( xvalue ) - 2;
  } else if( '\n' >< xvalue ) {
    l = strlen( xvalue ) - 1;
  } else {
    l = strlen( xvalue );
  }

  ret = 0;
  m = 1;
  if( l == 0 )
    return( 0 );

  # Remove the trailing spaces
  while( xvalue[l - 1] == " " && l > 0 )
    l--;

  for( i = l; i > 0; i-- ) {
    n = __hex_value( num:xvalue[i - 1] ) * m;
    ret += n;
    m = m * 16;
  }

  return int( ret );
}

# @brief Creates a HTTP GET request for "/" or a specific URL, sends
#        the request to the target, receives the response and extracts
#        the HTTP header (banner) without the body from the response.
#        If a header was received it is saved into the knowledge base.
#        If a header was requested which was requested previously the cached
#        header will be returned instead of doing a new request.
#
# @param port          The HTTP port of the target.
# @param file          The URL/file to request, defaults to "/".
# @param ignore_broken Returns the banner even if the remote host was known to be "broken".
#
# @return The header of the remote host or NULL if no response was received, no port parameter was passed or the remote port wasn't scanned.
#
function http_get_remote_headers( port, file, ignore_broken ) {

  local_var port, file, ignore_broken;
  local_var sb, banner, req, soc, body;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_remote_headers" );
    return NULL;
  }

  if( ! get_port_state( port ) )
    return NULL;

  if( ! file )
    file = "/";

  sb = strcat( "www/real_banner/", port, file );
  banner = get_kb_item( sb );
  if( banner )
    return banner;

  # nb: This is set in nasl/nasl_builtin_find_service.c of openvas-scanner as well but without a trailing "/"
  # like e.g. www/banner/80. In the case of this function we want to use the trailing "/" because the scanner
  # is saving the whole response including the body in that KB entry. This is not something we want to return
  # with this function.
  sb = strcat( "www/banner/", port, file );
  banner = get_kb_item( sb );
  if( banner )
    return banner;

  if( ! ignore_broken && http_get_is_marked_broken( port:port, host:"*" ) )
    return NULL; # TBD: Really return NULL if marked as broken? We still could use the banner version in VTs...

  # nb: Always keep http_get() before http_open_socket() as the first could
  # fork with multiple vhosts and the child's would share the same socket
  # causing race conditions and similar.
  req = http_get( item:file, port:port );
  soc = http_open_socket( port );
  if( ! soc )
    return NULL;

  send( socket:soc, data:req );
  banner = http_recv_headers2( socket:soc );
  #body = http_recv_body( socket:soc, headers:banner ); # TBD: What's the purpose of this?
  http_close_socket( soc );

  if( banner )
    replace_kb_item( name:sb, value:banner );

  return banner;
}

# @brief Returns all HTTP ports of the target system which are saved
#        in the KB entry "Services/www" found by the scanner. If no
#        ports were found open or no "default" parameter is passed
#        (if "nodefault" isn't set to TRUE) it will exit. In the case
#        where the "unscanned_closed" scanner setting is set to "no"
#        it will return the port passed via the default parameter.
#
# @param default             The port to return if "unscanned_closed" is set to "no" and no ports have been found open.
# @param nodefault           Don't exit if no "default" parameter is passed, it still will return if no HTTP servers are detected at all.
# @param host                The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#                            parameter or get_host_name) of the remote server. If no host parameter
#                            is passed http_host_name will be called automatically and a debug
#                            message is logged into the KB (currently commented out).
# @param ignore_broken       Returns the ports even if they are known to be "broken".
# @param ignore_unscanned    Returns the ports even if they were "unscanned" previously.
# @param ignore_cgi_disabled Returns the ports even if CGI scanning is disabled.
# @param dont_use_vhosts     Allows to specify if http_host_name is called internally (which would fork on multiple vhosts).
#
# @return The open / found HTTP ports or the port passed via the default parameter in the case of no found ports
#         and "unscanned_closed" is set to "no".
#
function http_get_port( default, nodefault, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts ) {

  local_var default, nodefault, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts;
  local_var port;
  # nb: optimize_test_enabled is a global var

  if( ! default && ! nodefault ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#http_get_port" );
    exit( 0 );
  }

  # nb: Keep before the forking get_kb_item call from below
  if( ! ignore_cgi_disabled ) {
    if( http_is_cgi_scan_disabled() ) {
      if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
        set_kb_item( name:"vt_debug_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#http_get_port" );
      }
      exit( 0 );
    }
  }

  port = get_kb_item( "Services/www" ); # nb: This will fork on multiple open ports
  if( port )
    default = port;

  # nb: If this is the case we haven't found an open port, default wasn't passed
  # and nodefault was set to TRUE. We can't continue in this case.
  if( ! default )
    exit( 0 );

  if( ! ignore_unscanned && ! get_port_state( default ) )
    exit( 0 );

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( port_is_marked_fragile( port:default ) )
    exit( 0 );

  if( ! dont_use_vhosts && ! host ) {
    host = http_host_name( dont_add_port:TRUE );
    #set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_get_port" );
  } else if( ! host ) {
    host = "*";
  }

  if( ! ignore_broken && http_get_is_marked_broken( port:default, host:host ) )
    exit( 0 );

  return default;
}

# @brief Returns all HTTP ports of the target system which are saved in
#        the KB entry "Services/www" found by the scanner. If no ports
#        were found open or no list is passed to the "default_port_list"
#        parameter the function will return an empty list. In the case
#        where the "unscanned_closed" scanner setting is set to "no" it
#        will return a default set of HTTP ports (namely 80, 443, 8008,
#        8080 and 8088) or (if passed) the ports included in the list of
#        the default_port_list parameter.
#
# @note  In contrast to @ref http_get_port this function will not fork
#        and return a list instead. This should be used e.g. for
#        Detection-VTs where we want to make sure that we're not getting
#        blocked by the remote service with to many concurrent connections.
#
# @param default_port_list   The list of ports to return (overwriting the internal defaults) if "unscanned_closed"
#                            is set to "no" and no ports have been found open.
# @param host                The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#                            parameter or get_host_name) of the remote server. If no host parameter
#                            is passed http_host_name will be called automatically and a debug
#                            message is logged into the KB (currently commented out).
# @param ignore_broken       Returns the ports even if they are known to be "broken".
# @param ignore_unscanned    Returns the ports even if they were "unscanned" previously.
# @param ignore_cgi_disabled Returns the ports even if CGI scanning is disabled.
# @param dont_use_vhosts     Allows to specify if http_host_name is called internally (which would fork on multiple vhosts).
#
# @return The open / found HTTP ports, if none were found an empty list. In the case of no found ports and
#         "unscanned_closed" is set to "no" a set of default ports or the list passed to the default_port_list
#         parameter.
#
function http_get_ports( default_port_list, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts ) {

  local_var default_port_list, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts;
  local_var final_port_list, check_port_list, default_ports, num_ports, ports, _port;

  final_port_list = make_list();
  check_port_list = make_list();
  default_ports = make_list( 80, 443, 8008, 8080, 8088 );
  num_ports = 0;

  if( ! ignore_cgi_disabled ) {
    if( http_is_cgi_scan_disabled() ) {
      if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
        set_kb_item( name:"vt_debug_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#http_get_ports" );
      }
      return final_port_list;
    }
  }

  ports = get_kb_list( "Services/www" );
  if( ports && typeof( ports ) == "array" ) {
    foreach _port( ports ) {
      num_ports++;
      check_port_list = make_list( check_port_list, _port );
    }
  }

  if( num_ports == 0 ) {
    if( default_port_list && typeof( default_port_list ) == "array" )
      check_port_list = default_port_list;
    else
      check_port_list = default_ports;
  }

  if( ! dont_use_vhosts && ! host ) {
    host = http_host_name( dont_add_port:TRUE );
    #set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_get_ports" );
  } else if( ! host ) {
    host = "*";
  }

  foreach _port( check_port_list ) {

    if( ! ignore_unscanned && ! get_port_state( _port ) )
      continue;

    # Includes e.g. PJL ports which are printing everything
    # sent to them so don't include them here.
    if( port_is_marked_fragile( port:_port ) )
      continue;

    if( ! ignore_broken ) {
      if( http_get_is_marked_broken( port:_port, host:host ) )
        continue;
    }

    final_port_list = make_list( final_port_list, _port );
  }
  return final_port_list;
}

# @brief Checks if the remote web server is responding to a HTTP GET request.
#
# @param port  The port of the remote server to check.
# @param retry The amount of retries until the check is considered as failed.
#              This parameter is optional and defaults to 2 retries and is
#              limited to a max. of 5 retries.
#
# @return TRUE if the remote web server is not responding, FALSE otherwise and NULL if no port was passed.
#
function http_is_dead( port, retry ) {

  local_var port, retry;
  local_var url, req, i, soc, code, h, h2, b;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_is_dead" );
    return NULL;
  }

  if( ! retry )
    retry = 2;

  if( retry > 5 )
    retry = 5; # nb: Limit the amount of retries to a sane default

  # nb: http_head does not work against SWAT & VNC (& probably others...)
  # nb: Always keep http_get() before http_open_socket() as the first could
  # fork with multiple vhosts and the child's would share the same socket
  # causing race conditions and similar.
  url = strcat( "/OpenVASTest", rand(), ".html" );
  req = http_get( item:url, port:port );

  i = 0;
  soc = http_open_socket( port );
  while( ! soc && i++ < retry ) {
    sleep( i );
    soc = http_open_socket( port );
    if( _http_debug ) display( "DEBUG: i = ", i, "\n" );
  }

  if( ! soc )
    return TRUE;

  send( socket:soc, data:req );
  code = recv_line( socket:soc, length:1024 );
  if( code ) {
    h = http_recv_headers2( socket:soc );
    h2 = strcat( code, h );
    b = http_recv_body( socket:soc, headers:h2 );
  }
  http_close_socket( soc );
  if( ! code )
    return TRUE;

  # 500: internal server error
  # 501: not implemented = unsupported method...
  # 502: Bad gateway = upstream server sends an invalid response
  # 503: service unavailable = temporary overloading...
  # 504: gateway timeout = no timely response from upstream server
  if( ereg( pattern:"^HTTP/1\.[01] +50[234]", string:code ) )
    return TRUE;
  else
    return FALSE;
}

# @brief Receives the HTTP header from a specified socket.
#
# @param socket The existing socket to receive the header from.
#
# @return A string containing the HTTP header or NULL if none was
#         received or no socket parameter was passed.
#
function http_recv_headers2( socket ) {

  local_var socket;
  local_var counter, line, buf;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv_headers2" );
    return NULL;
  }

  while( TRUE ) {
    counter++;
    line = recv_line( socket:socket, length:4096 );
    buf += line;
    if( line == '\r\n' )
      break;
    if( ! strlen( line ) )
      break;
    if( strlen( line ) == 1 && line =~ '^\x0a$' )
      break;
    if( counter > 1024 )
      break;
  }

  return buf;
}

# @brief Receives the HTTP body from a specified socket.
#
# @param socket  The existing socket to receive the body from.
# @param headers A previously received header used instead of getting the header with a new request.
# @param length  The length / amount of data to receive. See the @note below for some more info.
#
# @return A string containing the HTTP body or NULL if none was
#         received or no socket parameter was passed.
#
# @note This function does not return the headers! So 'length' parameter does not include headers length, even if we
#       have to read them. If Content-length is set, "length" only allows the function to read more data, if available.
#       i.e., it is ignored most of the time.
#
function http_recv_body( socket, headers, length ) {

  local_var socket, headers, length;
  local_var h, l, gzip, cl, max, min, body, tmp, x, n;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv_body" );
    return NULL;
  }

  if( ! headers ) {
    h = http_recv_headers2( socket:socket );
  } else {
    h = headers;
  }

  l = -1;

  if( egrep( pattern:"^Content-Encoding\s*:\s*gzip", string:h, icase:TRUE ) )
    gzip = TRUE;

  cl = egrep( pattern:"^Content-Length\s*:\s*[0-9]+", string:h, icase:TRUE );
  if( cl )
    l = int( ereg_replace( pattern:"Content-Length\s*:\s*([0-9]+).*", replace:"\1", string:cl, icase:TRUE ) );

  # nb: "l" = Content-Length or -1 now

  max = -1;
  min = -1;

  if( l < 0 && egrep( pattern:"^Transfer-Encoding\s*:\s*chunked", string:h, icase:TRUE ) ) {

    body = "";

    while( 1 ) {
      tmp = recv_line( socket:socket, length:4096 );
      if( ! tmp )
        l = 0;
      else
        l = hex2dec( xvalue:tmp );
      body = strcat( body, recv( socket:socket, length:l, min:l ) );
      # "\r\n"
      recv( socket:socket, length:2, min:2 );
      if( l == 0 ) {
        return( body ); # This is expected - don't put this line before the previous
      }
    }
  }

  if( length )
    max = length;

  if( l >= 0 )
    min = int( l );
  if( l >= max || min >= max )
    max = l;

  if( max < 0 ) {
    if( _http_debug ) display( "DEBUG: http_recv_body: bogus or no Content-length field, and no 'length' parameter set! Defaulting to 32 KB\n" );
    max = 32768;
  }

  if( _http_debug ) display( "DEBUG: http_recv_body: min=", min, "; max=", max, "\n" );

  if( min > 0 ) {
    x = recv( socket:socket, length:max, min:min );
  } else {
    n = recv( socket:socket, min:max, length:max );
    x = n;
    while( strlen( n ) >= max && max != 0 ) {
      n = recv( socket:socket, length:max );
      x += n;
      if( strlen( x ) > 1048576 ) {
        if( _http_debug ) display( "DEBUG: http_recv_body: read stopped after 1 MB!\n" );
        break;
      }
    }
  }

  if( gzip && x )
    return http_gunzip( buf:x, onlybody:FALSE );
  else
    return( x );
}

# @brief Reads all received HTTP data (header and body) from a specified socket.
#
# @param socket The existing socket to receive the data from.
# @param code   TBD: What's the purpose of this parameter?
#
# @return A string containing the HTTP data or NULL if none was
#         received or no socket parameter was passed.
#
function http_recv( socket, code ) {

  local_var socket, code;
  local_var h, l, b;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv" );
    return NULL;
  }

  if( code ) {
    h = strcat( code ); # Convert to string, just in case
    repeat {
      l = recv_line( socket:socket, length:2048 );
      h += l;
    } until( ! l || l =~ '^[\r\n]+$' ); # EOF or empty line

    if( ! l )
      return h;

  } else {
    h = http_recv_headers2( socket:socket );

    if( ! h )
      return NULL;
    else if( ! ereg( pattern:"^HTTP/.* [0-9]*", string:h ) )
      return h;

    h = strcat( h, '\r\n' );
  }

  b = http_recv_body( socket:socket, headers:h, length:0 );
  return strcat( h, b );
}

# @brief Reads all received HTTP data (header and body) from a specified socket
#        up to the specified length.
#
# @param socket     The existing socket to receive the data from.
# @param bodylength The amount/length of the data to receive (optional).
#
# @return A string containing the HTTP data or NULL if none was
#         received or no socket parameter was passed.
#
# @note The bodylength will be ignored if the Content-length field is set.
#
function http_recv_length( socket, bodylength ) {

  local_var socket, bodylength;
  local_var h, b;

  if( ! socket ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#http_recv_length" );
    return NULL;
  }

  h = http_recv_headers2( socket:socket );
  b = http_recv_body( socket:socket, headers:h, length:bodylength );
  return strcat( h, '\r\n', b );
}

# @brief Sends a HTTP request to the target and reads all received data (header and body) from
#        the response.
#
# @param port The port of the remote server to send the data to.
# @param data The data to sent to the remote server.
#
# @return A string containing the received HTTP data or NULL if none was
#         received or no port or data parameter was passed.
#
# @note A valid HTTP request needs to be passed to the data parameter. Some basic sanity checks are
#       done by this function and it will report any invalid data into the KB for later evaluation.
#
function http_send_recv( port, data ) {

  local_var port, data;
  local_var oid, user_agent, oid_str, s, x, cl, conlen, r;
  # nb: _http_debug is a global var

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_send_recv" );
    return NULL;
  }

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_send_recv" );
    return NULL;
  }

  # nb: We should expect at least a request like: "GET / HTTP/1.1\r\n\r\n" (length: 18).
  # But for some specific cases we're just checking for some less data.
  if( strlen( data ) < 8 || data !~ "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL).*HTTP/(1\.[01]|2)" ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.900522" && # secpod_ziproxy_server_detect.nasl might require the wrong request to trigger the detection
        oid != "1.3.6.1.4.1.25623.1.0.10730" &&  # pre2008/raptor_detect.nasl as well
        oid != "1.3.6.1.4.1.25623.1.0.153974" )  # 2025/gb_http_allowed_methods.nasl as well
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_send_recv(): Invalid HTTP request (length < 8, invalid HTTP method or missing HTTP/ header) passed in 'data' variable." );
  }

  # http_get() won't add a Host: header if only HTTP/1.0 support was detected
  # nb: Commented out for now as quite a lot older VTs are probably passing a HTTP request without the Host: header
  #if( "Host: " >!< data && " HTTP/1.0" >!< data ) {
  #  oid = get_script_oid();
  #  if( oid != "1.3.6.1.4.1.25623.1.0.802045" ) # nb: gb_linux_rootkit_nginx_iframe_injection.nasl requires a wrong host header
  #    set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#http_send_recv(): No 'Host:' header passed in 'data' variable. This might lead to issues if SNI is enabled on the remote host." );
  #}

  if( data !~ "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL) (/|\.+/|https?:|\*).* HTTP" ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.103293" && # gb_apache_49957.nasl requires sending a @localhost URI
        oid != "1.3.6.1.4.1.25623.1.0.17230"  && # cern_httpd_access_ctrl.nasl requires sending a \ at the start of the URI
        oid != "1.3.6.1.4.1.25623.1.0.900522" && # secpod_ziproxy_server_detect.nasl might require the wrong request to trigger the detection
        oid != "1.3.6.1.4.1.25623.1.0.10730" &&  # pre2008/raptor_detect.nasl as well
        oid != "1.3.6.1.4.1.25623.1.0.153974" )  # 2025/gb_http_allowed_methods.nasl as well
      set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#http_send_recv(): URL/URI of the HTTP request passed in 'data' variable doesn't start with one of the following: '/, ./, http, *'." );
  }

  # Some (mostly older) VTs are not passing the User-Agent header but we should always have one.
  if( " HTTP/1.1" >< data && ! egrep( pattern:"^User-Agent:.+", string:data, icase:TRUE ) ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.114542" ) { # 2024/expressjs/gb_expressjs_debug_mode_http.nasl, we don't want to exclude the User Agent here on purpose
      data = ereg_replace( string:data, pattern:'\r\n\r\n', replace:'\r\nUser-Agent: ' + http_get_user_agent() + '\r\n\r\n' );
      set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#http_send_recv(): Using a HTTP/1.1 request without a 'User-Agent:' header passed in 'data' variable. Adding it automatically to the request." );
    }
  }

  if( http_ua_include_oid() && user_agent = egrep( pattern:"^User-Agent:.+", string:data, icase:TRUE ) ) {
    user_agent = chomp( user_agent );
    oid_str = "(OID:" + get_script_oid() + ")";
    if( oid_str >!< user_agent )
      data = str_replace( string:data, find:user_agent, replace:user_agent + " " + oid_str );
  }

  if( _http_debug ) display( "DEBUG: http_send_recv( port: ", port, ", data: ", data, " )\n" );

  s = http_open_socket( port );
  if( ! s )
    return;

  send( socket:s, data:data );
  while( x = http_recv( socket:s ) ) {
    if( egrep( pattern:"^Content-Length\s*:", string:x, icase:TRUE ) &&
        "206 Partial" >!< x ) {
      cl = eregmatch( pattern:"Content-Length\s*:\s*([0-9]+)", string:x, icase:TRUE );
      if( ! isnull( cl[1] ) )
        conlen = int( cl[1] );
    }

    r += x;
    if( ( conlen && conlen > 0 ) && strlen( r ) >= conlen )
      break;
  }

  http_close_socket( s );

  if( egrep( pattern:"^Content-Encoding\s*:\s*gzip", string:r, icase:TRUE ) )
    return http_gunzip( buf:r );
  else
    return r;
}

# @brief Returns the detected directories (e.g. by webmirror.nasl and/or
#        DDI_Directory_Scanner.nasl) on the remote web server. Additionally
#        it includes all user specified directories via the scanner preference
#        'cgi_path'. If CGI Scanning is disabled the function will exit.
#
# @param port The port of the remote server for which the detected directories
#             should be returned. This parameter is optional and if not passed
#             the directories of all web servers on the remote host are returned.
# @param host The hostname of the remote server (e.g. from http_host_name with the
#             dont_add_port:TRUE parameter or get_host_name) for which the detected
#             directories should be returned. This parameter is optional and if not
#             passed the directories of all web servers and all hostnames of the
#             remote host are returned.
#
# @return The directories on the remote web server as defined in the description above.
#
function http_cgi_dirs( port, host ) {

  local_var port, host;
  local_var kb, usercgis;
  # nb: optimize_test_enabled is a global var

  if( ! port )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_cgi_dirs" );

  if( http_is_cgi_scan_disabled() ) {
    if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
      set_kb_item( name:"vt_debug_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#http_cgi_dirs()" );
    }
    #return NULL; # Old behaviour
    exit( 0 ); # Throws a "nasl_array_iterator: unhandled type 57" message if http_cgi_dirs() is called within a foreach but not within a make_list()
  }

  # TBD: Use http_host_name(dont_add_port:TRUE) if(!host) ?
  # This would require an additional parameter to skip this if
  # the VT dev wants to get the directories of all hosts...

  if( port && host ) {
    kb = get_kb_list( "www/" + host + "/" + port + "/content/directories" );
  } else if( port && ! host ) {
    kb = get_kb_list( "www/*/" + port + "/content/directories" );
  } else if( ! port && host ) {
    kb = get_kb_list( "www/" + host + "/*/content/directories" );
  } else {
    kb = get_kb_list( "www/*/*/content/directories" );
  }

  usercgis = get_kb_list( "/user/cgis" );
  if( isnull( usercgis ) ) usercgis = "/";
  if( isnull( kb ) ) {
    kb = make_list( usercgis, "/" );
  } else {
    kb = make_list( usercgis, kb, "/" );
  }

  return( make_list_unique( kb ) );
}

# @brief Returns if a remote web server is able to host or support hosting PHP files.
#
# @param port The port of the remote server to check.
#
# @note Please add a dependency to the following VTs if this function is used within a VT:
#       - gb_php_http_detect.nasl (Is setting the "can_host_php" KB key if PHP was detected)
#       - webmirror.nasl (Is setting the info provided by http_get_kb_file_extensions())
#       - DDI_Directory_Scanner.nasl (required so that webmirror.nasl can crawl the remote host
#         in more detail)
#
# @note Additional product detection VTs might also set the relevant KB key extending the coverage
#       / reliability of this function.
#
# @note This function is (at least currently) working on a port base (and not including a possible
#       vhost / hostname) on purpose as if a web server is e.g. supporting PHP scripts on vhost1 it
#       should also support them on vhost2.
#
# @return TRUE if the remote web server is able to host or support hosting PHP files,
#         FALSE otherwise and NULL in the case where no port parameter was passed.
#
function http_can_host_php( port ) {

  local_var port;
  local_var key, can_host, files, banner, can_host_pattern, cant_host_pattern;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_can_host_php" );
    return NULL;
  }

  # nb: We're using "yes/no" for the keys as a FALSE won't be saved into the KB.
  key = "www/" + port + "/can_host_php";
  if( can_host = get_kb_item( key ) ) {
    if( can_host == "yes" )
      return TRUE;
    else
      return FALSE;
  }

  if( get_kb_item( "www/" + port + "/PHP" ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  # nb: * in host is expected as webserver hosting .php* files on one vhost
  # is most likely supporting PHP on another vhost as well.
  files = http_get_kb_file_extensions( port:port, host:"*", ext:"php*" );
  if( ! isnull( files ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  banner = http_get_remote_headers( port:port );
  if( ! banner ) {
    set_kb_item( name:key, value:"no" );
    return FALSE; # Broken Web Server
  }

  if( egrep( pattern:"((powered|server).*php|set-cookie\s*:.*phpsessid|content-type\s*:\s*application/x-appweb-php|daap-server\s*:\s*ampache)", string:banner, icase:TRUE ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  can_host_pattern  = "(apache|nginx|thttpd|aolserver|pi3web|zeus|iis|icewarp|lighttpd|";
  can_host_pattern += "hiawatha|litespeed|caddy|panweb|embedthis-http|embedthis-appweb|mbedthis-appweb|";
  can_host_pattern += "Oracle-iPlanet-Web-Server|Sun-Java-System-Web-Server|Sun-ONE-Web-Server|";
  can_host_pattern += "CompaqHTTPServer/[0-9.]+ HPE? System Management Homepage)";
  if( egrep( pattern:"^Server\s*:.*" + can_host_pattern, string:banner, icase:TRUE ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  cant_host_pattern  = "(user-agent\s*:\s*loolwsd wopi|x-powered-by\s*:\s*express|";
  cant_host_pattern += "^Server\s*:.*(sdk for upnp|miniupnp|NessusWWW|MiniServ|pve-api-daemon|ZNC|(microsoft-)?cassini)|^DAAP-Server\s*:)";
  if( egrep( pattern:cant_host_pattern, string:banner, icase:TRUE ) ) {
    set_kb_item( name:key, value:"no" );
    return FALSE; # We know that this can't host a PHP website
  }

  set_kb_item( name:key, value:"yes" );
  return TRUE; # Unknown web server or Server: banner hidden - might be able to host a PHP website
}

# @brief Returns if a remote web server is able to host or support hosting .asp and/or .aspx files.
#
# @param port The port of the remote server to check.
#
# @note Additional product detection VTs might also set the relevant KB key extending the coverage
#       / reliability of this function.
#
# @note This function is (at least currently) working on a port base (and not including a possible
#       vhost / hostname) on purpose as if a web server is e.g. supporting ASP scripts on vhost1 it
#       should also support them on vhost2.
#
# @return TRUE if the remote web server is able to host or support hosting .asp and/or .aspx files,
#         FALSE otherwise and NULL in the case where no port parameter was passed.
#
function http_can_host_asp( port ) {

  local_var port;
  local_var key, can_host, files, banner, can_host_pattern, cant_host_pattern;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_can_host_asp" );
    return NULL;
  }

  # nb: We're using "yes/no" for the keys as a FALSE won't be saved into the KB.
  key = "www/" + port + "/can_host_asp";
  if( can_host = get_kb_item( key ) ) {
    if( can_host == "yes" )
      return TRUE;
    else
      return FALSE;
  }

  # nb: * in host is expected as webserver hosting .asp* files on one vhost
  # is most likely supporting .asp/.aspx on another vhost as well.
  files = http_get_kb_file_extensions( port:port, host:"*", ext:"asp*" );
  if( ! isnull( files ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  banner = http_get_remote_headers( port:port );
  if( ! banner ) {
    set_kb_item( name:key, value:"no" );
    return FALSE; # Broken Web Server
  }

  if( egrep( pattern:"((powered|server).*asp|set-cookie\s*:.*(asp\.net_sessionid|aspsessionid)|x-aspnet(mvc)?-version|x-owa-version\s*:|MicrosoftSharePointTeamServices\s*:)", string:banner, icase:TRUE ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  can_host_pattern = "(iis|goahead-webs|(microsoft-)?cassini|microsoft-wince)";
  if( egrep( pattern:"^Server\s*:.*" + can_host_pattern, string:banner, icase:TRUE ) ) {
    set_kb_item( name:key, value:"yes" );
    return TRUE;
  }

  cant_host_pattern  = "(user-agent\s*:\s*loolwsd wopi|x-powered-by\s*:\s*express|";
  cant_host_pattern += "^Server\s*:.*(sdk for upnp|miniupnp|NessusWWW|MiniServ|Apache|nginx|";
  cant_host_pattern += "pve-api-daemon|ZNC|lighttpd|Oracle-iPlanet-Web-Server|";
  cant_host_pattern += "Sun-Java-System-Web-Server|Sun-ONE-Web-Server)|^DAAP-Server\s*:|";
  cant_host_pattern += "CompaqHTTPServer/[0-9.]+ HPE? System Management Homepage)";
  if( egrep( pattern:cant_host_pattern, string:banner, icase:TRUE ) ) {
    set_kb_item( name:key, value:"no" );
    return FALSE; # We know that this can't host a ASP/ASP.NET website
  }

  set_kb_item( name:key, value:"yes" );
  return TRUE; # Unknown web server or Server: banner hidden - might be able to host a ASP/ASP.NET website
}

# @brief Unzips the received "content-encoding: gzip" HTTP data with gunzip.
#
# @param buf      The data to gunzip.
# @param onlybody If set to TRUE only the HTTP body is unzipped and returned.
#
# @return A string containing the unzipped data, a string without unzipped data
#         if no "content-encoding: gzip" was found or if the data was already
#         unzipped by this function and FALSE if no buf parameter was passed.
#
function http_gunzip( buf, onlybody ) {

  local_var buf, onlybody;
  local_var lines, _line, sep, header, body, h;

  if( ! buf ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#buf#-#http_gunzip" );
    return FALSE;
  }

  if( "##**##UNZIPPED##**##" >< buf )
    return buf;

  if( ! egrep( pattern:"^Content-Encoding\s*:\s*gzip", string:buf, icase:TRUE ) && ! onlybody )
    return buf;

  if( ! onlybody ) {

    lines = split( buf, keep:FALSE );

    foreach _line( lines ) {

      if( ! sep && _line !~ "^$" )
        header += _line + '\n';

      if( _line =~ "^$" && ! body ) {
        sep = TRUE;
        continue;
      }

      if( sep )
        body += _line + '\n';
    }
  } else {
    body = buf;
  }

  if( ! body )
    return buf;

  if( body = gunzip( data:body ) ) {

    if( onlybody )
      return body + '\n\n\n##**##UNZIPPED##**##';

    h = ereg_replace( string:header, pattern:'(content-encoding\\s*:\\s*[^\r\n]+[\r\n]+)', replace:"", icase:TRUE );
    return( h + '\r\n\r\n' + body + '\n\n\n##**##UNZIPPED##**##' );
  }
  return buf;
}

# @brief Returns the hostname of the remote HTTP server. If the port parameter is passed the
#        function is also adding the port of the remote server to the hostname if the port is not
#        80 and not 443. If no port is passed the dont_add_port parameter needs to be set to TRUE.
#
# @note If the called get_host_name() function provided by the scanner returns NULL/no data there is
#       a fallback included to provide/return the IP (via get_host_ip()) instead.
#
# @param port          The port of the remote server.
# @param use_ip        If set to TRUE the IP of the remote server is returned, otherwise the hostname.
# @param dont_add_port If set to TRUE no port is added to the IP/hostname, otherwise the port is added.
#
# @return The hostname or IP of the remote server controlled by the described parameters.
#
function http_host_name( port, use_ip, dont_add_port ) {

  local_var port, use_ip, dont_add_port;
  local_var host;

  if( use_ip )
    host = get_host_ip();
  else
    host = get_host_name();

  # nb: Just in case, at least for "openvas-nasl" on command line we have seen get_host_name()
  # returning NULL / nothing for specific targets.
  if( ! host )
    host = get_host_ip();

  if( dont_add_port )
    return host;

  if( ! port )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_host_name" );

  if( port ) {
    # nb: Some IPS/WAF might block our requests if we're adding a port to the
    # Host: header so at least don't include it for 80 and 443 which complies
    # with the RFC.
    if( port != 80 && port != 443 )
      host += ":" + port;
  }

  return host;
}

# @brief Extracts the url part of a "Location:" header from a 301/302 redirect response.
#        It makes also sure that the redirect is not pointing to a different server.
#
# Examples are e.g., for each "/foo" is returned:
# Location: https://example.com/foo (pointing to the same host)
# Location: http://example.com/foo (pointing to the same host)
# Location: //example.com/foo (pointing to the same host)
# Location: https://example.com/foo (pointing to a different host -> this needs to be ignored)
# Location: http://example.com/foo (to a different host -> this needs to be ignored)
# Location: //example.com/foo (to a different host -> this needs to be ignored)
# Location: /foo
# Location: foo (if current_dir is set to "/")
#
# If the dir_only parameter is set to TRUE then
#
# - for each of those "/foo" is returned:
#
# Location: https://example.com/foo/
# Location: https://example.com/foo/bar.php/foobar
# Location: https://example.com/foo/bar.php
# Location: https://example.com/foo
# Location: /foo/
# Location: /foo/bar.php/foobar
# Location: /foo/bar.php
# Location: /foo
# Location: foo/bar.php (if current_dir is set to "/")
#
# - for each of those "/foo/bar" is returned:
#
# Location: https://example.com/foo/bar/
# Location: https://example.com/foo/bar/bar.php/foobar
# Location: https://example.com/foo/bar/bar.php
# Location: https://example.com/foo/bar
# Location: /foo/bar/
# Location: /foo/bar/bar.php/foobar
# Location: /foo/bar/bar.php
# Location: /foo/bar
# Location: foo/bar/foobar.php (if current_dir is set to "/")
# Location: bar/foobar.php (if current_dir is set to "/foo")
#
# @param port        The port of the remote server.
# @param data        The data to extract the location from.
# @param debug       If set to TRUE additional debugging infos on the location extraction is displayed on command line / the scanner log.
# @param dir_only    If set to TRUE only the directory (without the trailing "/") is returned in redirects including scripts with file
#                    extensions like /foo/bar.php.
# @param current_dir The (mandatory) current dir like e.g. "/foo" or "/" which needs to be passed by the calling VT and which is used to
#                    determine the redirect if something like "Location: index.php" is passed.
#
# @return The extracted location from the data or NULL if no "Location:" header was found, no port or data parameter was passed or the
#         redirect is pointing to a different host. Note that if "dir_only" is set to TRUE the function is always returning the directory
#         without a trailing "/" (e.g. "/foo" and not "/foo/"). Only the special "/" is returning "as is".
#
# @todo What to do if a redirect is pointing from e.g. 80 to 443?
#
function http_extract_location_from_redirect( port, data, debug, dir_only, current_dir ) {

  local_var port, data, debug, dir_only, current_dir;
  local_var passed_dir, location_header, location_target, location_host, host, ip, _location, return_location;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_extract_location_from_redirect" );
    return;
  }

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_extract_location_from_redirect" );
    return;
  }

  if( ! current_dir ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_extract_location_from_redirect(): No 'current_dir' passed, assuming '/'." );
    current_dir = "/";
  }

  if( debug || _http_debug ) display( 'DEBUG: Uses current_dir: "' + current_dir + '"' );

  # Return directly if we don't have a location header in the data or the header is empty.
  location_header = egrep( string:data, pattern:"^Location\s*:\s*[^\r\n]+", icase:TRUE );
  if( ! location_header ) {
    if( debug || _http_debug ) display( "DEBUG: Empty or missing Location header." );
    return;
  }

  location_header = chomp( location_header );
  if( location_header =~ "^Location\s*:$" ) {
    if( debug || _http_debug ) display( 'DEBUG: Empty Location header received: "' + location_header + '"' );
    return;
  }

  if( debug || _http_debug ) display( 'DEBUG: Location header is: "' + location_header + '"' );

  # Grab everything after Location:
  location_target = ereg_replace( string:location_header, pattern:"Location\s*:\s*(.+)$", replace:"\1", icase:TRUE );

  if( debug || _http_debug ) display( 'DEBUG: Location header after removing the "Location:" prefix is: "' + location_target + '"' );

  # nb:
  # - Make sure that we always have a current_dir without a trailing "/"
  # - only the "/" current_dir is a special case which should be kept
  #
  passed_dir = current_dir;
  if( current_dir =~ "/$" && current_dir != "/" )
    current_dir = ereg_replace( string:current_dir, pattern:"/$", replace:"" );

  # nb: Handle "https://", "http://" and "//" links in the location header
  if( location_target =~ "^(https?:)?//" ) {

    location_host = ereg_replace( string:location_target, pattern:"^(https?:)?//([^/]*)/.*", replace:"\2", icase:TRUE );

    if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to host/ip: "' + location_host + '"' );

    ip   = get_host_ip();
    host = http_host_name( port:port );

    # nb: The location header is pointing to the same hostname / IP
    if( host >< location_host || ip >< location_host ) {

      _location = ereg_replace( string:location_target, pattern:"^(https?:)?//[^/]*/([^?]*)", replace:"/\2", icase:TRUE );

      if( dir_only ) {

        # nb:
        # - Catching "Location: https://example.com/foo/"
        # - For e.g. current_dir = "/" this should return "/foo" here
        #
        if( _location =~ "/$" ) {
          return_location = _location;
        }

        # nb:
        # - Catching e.g. "Location: https://example.com/foo/index.php"
        # - For redirects like e.g. "https://example.com/foo/bar" we don't know / can't guess if
        #   "bar" is actually a dir or a script
        # - For this reason the regex below tries do identify any script based on e.g. a dot or a
        #   question mark in the file name like e.g.:
        #   - https://example.com/foo/index.php
        #   - https://example.com/foo/index?foo=bar
        # - For e.g. current_dir = "/" and the examples above this should return "/foo" here
        #
        else if( _location =~ "([^/]*)/[^/]+(\.|\?)[^/]+" ) {

          _location = eregmatch( string:_location, pattern:"/(.*[^/]*)/[^/]+(\.|\?)[^/]+" );

          if( isnull( _location[1] ) )
            return_location = "/"; # nb: For cases like "/index.php" or "/index?foo=bar"
          else
            return_location = "/" + _location[1];
        }

        else {
          return_location = _location;
        }

        # nb:
        # - For the "dir_only = TRUE" case we're stripping the trailing "/" away as we want to
        #   return no trailing "/" for all "dir_only = TRUE" cases
        # - But only replace trailing "/" if return_location != "/"
        #
        if( return_location != "/" )
          return_location = ereg_replace( string:return_location, pattern:"/$", replace:"" );

        if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" on the same host/ip. dir_only parameter is set to TRUE, returning the "' + return_location + '" part of the location.' );
      }

      else {
        return_location = _location;

        if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" on the same host/ip. Returning the "' + return_location + '" part of the location.' );
      }

      return return_location;
    }

    # If its not pointing to the same hostname / IP we can't follow it
    else {

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" NOT on the same host/ip. NOT returning this location.' );

      return;
    }
  }

  # nb:
  # - Handle redirects like "Location: index.php", "Location: foo/" or "Location: foo/index.php"
  # - But exclude:
  #   - "Location: ../index.php" which needs to be separately handled at some point in time
  #   - "Location: ./index.php" which is getting handled differently down below
  #
  else if( location_target !~ "^/" && location_target !~ "^\.+/" ) {

    return_location = current_dir;
    if( current_dir != "/" )
      return_location += "/";

    if( dir_only ) {

      # nb:
      # - Catching "Location: foo/"
      # - For e.g. current_dir = "/" this should return "/foo" here
      #
      if( location_target =~ "/$" ) {
        return_location += location_target;
      }

      # nb:
      # - Catching e.g. "Location: foo/index.php"
      # - For redirects like e.g. "foo/bar" we don't know / can't guess if "bar" is actually a dir
      #   or a script
      # - For this reason the regex below tries do identify any script based on e.g. a dot or a
      #   question mark in the file name like e.g.:
      #   - foo/index.php
      #   - foo/index?foo=bar
      # - For e.g. current_dir = "/" and the examples above this should return "/foo" here
      #
      else if( location_target =~ "([^/]*)/[^/]+(\.|\?)([^/]+|$)" ) {

        _location = eregmatch( string:location_target, pattern:"(.*[^/]*)/[^/]+(\.|\?)([^/]+|$)" );

        if( ! isnull( _location[1] ) ) { # nb: Shouldn't happen...
          return_location += _location[1];
        }
      }

      # nb:
      # - Catching "Location: foo" or similar without a file extension / query parameter
      # - Note that we're assuming that "foo" is a directory as we can't guess if this is a file or
      #   a dir...
      else if( "." >!< location_target && "?" >!< location_target ) {
        return_location += location_target;
      }

      # nb:
      # - And finally for all "Location: index.php" or similar with a file extension or everything
      #   else we're doing nothing and just return the plain location
      # - For the "dir_only = TRUE" case we're stripping the trailing "/" away as we want to return
      #   no trailing "/" for all "dir_only = TRUE" cases
      # - But only replace trailing "/" if return_location != "/"
      if( return_location != "/" )
        return_location = ereg_replace( string:return_location, pattern:"/$", replace:"" );

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" (a relative path to the passed current dir "' + passed_dir + '") on the same host/ip. dir_only parameter is set to TRUE, returning "' + return_location + '" as the location.' );
    }

    else {

      return_location += location_target;

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" (a relative path to the passed current dir "' + passed_dir + '") on the same host/ip. Returning "' + return_location + '" as the location.' );
    }

    return return_location;
  }

  # nb: Handle e.g.:
  # Location: ./foo
  # Location: ./index.php
  # Location: ./foo/bar.php
  else if( location_target =~ "^\./" ) {

    if( dir_only ) {

      # nb:
      # - Catching "Location: ./foo/"
      # - For e.g. current_dir = "/" this should return "/foo" here
      #
      if( location_target =~ "/$" ) {
        return_location = location_target;
      }

      # nb:
      # - Catching e.g. "Location: ./foo/index.php"
      # - For redirects like e.g. "./foo/bar" we don't know / can't guess if "bar" is actually a dir
      #   or a script
      # - For this reason the regex below tries do identify any script based on e.g. a dot or a
      #   question mark in the file name like e.g.:
      #   - ./foo/index.php
      #   - ./foo/index?foo=bar
      # - For e.g. current_dir = "/" and the examples above this should return "/foo" here
      #
      else if( location_target =~ "([^/]*)/[^/]+(\.|\?)([^/]+|$)" ) {

        _location = eregmatch( string:location_target, pattern:"\./(.*[^/]*)/[^/]+(\.|\?)([^/]+|$)" );

        if( isnull( _location[1] ) )
          return_location = "./"; # nb: For cases like "./index.php"
        else
          return_location = "./" + _location[1];
      }

      # nb: Everything else
      else {
        return_location = location_target;
      }

      # nb:
      # - For the "dir_only = TRUE" case we're stripping the trailing "/" away as we want to return
      #   no trailing "/" for all "dir_only = TRUE" cases
      # - But only replace trailing "/" if return_location != "./"
      if( return_location != "./" )
        return_location = ereg_replace( string:return_location, pattern:"/$", replace:"" );

      # nb:
      # - And finally we need to replace the "./" with our "current_dir"
      # - replacement pattern depends on the current "return_location" value
      if( return_location == "./" )
        return_location = ereg_replace( string:return_location, pattern:"^(\./)", replace:current_dir );
      else
        return_location = ereg_replace( string:return_location, pattern:"^(\.)", replace:current_dir );

      # nb: Sometimes we're getting e.g. "//foo" here so just replace "//" by "/"
      return_location = ereg_replace( string:return_location, pattern:"^(//)", replace:"/" );

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" on the same host/ip. dir_only parameter is set to TRUE, returning "' + return_location + '" as the location.' );
    }

    else {

      return_location = location_target;

      # For this case we're just replacing the "./" by:
      # - "current_dir" if current_dir is just "/"
      # - "current_dir + /" for all other cases
      if( current_dir == "/" )
        return_location = ereg_replace( string:return_location, pattern:"^(\./)", replace:current_dir );
      else
        return_location = ereg_replace( string:return_location, pattern:"^(\./)", replace:current_dir + "/" );

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + return_location + '" on the same host/ip. Returning this location.' );
    }

    return return_location;
  }

  # nb:
  # - Handle remaining redirects like "Location: /foo"
  # - Note that this currently can't handle something like "Location: ../index.php"
  else {

    if( dir_only ) {

      # nb:
      # - Catching "Location: /foo/"
      # - For e.g. current_dir = "/" this should return "/foo" here
      #
      if( location_target =~ "/$" ) {
        return_location = location_target;
      }

      # nb:
      # - Catching e.g. "Location: /foo/index.php"
      # - For redirects like e.g. "/foo/bar" we don't know / can't guess if "bar" is actually a dir
      #   or a script
      # - For this reason the regex below tries do identify any script based on e.g. a dot or a
      #   question mark in the file name like e.g.:
      #   - /foo/index.php
      #   - /foo/index?foo=bar
      # - For e.g. current_dir = "/" and the examples above this should return "/foo" here
      #
      # Catching "Location: "
      else if( location_target =~ "([^/]*)/[^/]+(\.|\?)([^/]+|$)" ) {

        _location = eregmatch( string:location_target, pattern:"/(.*[^/]*)/[^/]+(\.|\?)([^/]+|$)" );

        if( isnull( _location[1] ) )
          return_location = "/"; # nb: For cases like "/index.php"
        else
          return_location = "/" + _location[1];
      }

      # nb: Everything else
      else {
        return_location = location_target;
      }

      # nb:
      # - For the "dir_only = TRUE" case we're stripping the trailing "/" away as we want to return
      #   no trailing "/" for all "dir_only = TRUE" cases
      # - But only replace trailing "/" if return_location != "/"
      if( return_location != "/" )
        return_location = ereg_replace( string:return_location, pattern:"/$", replace:"" );

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + location_target + '" on the same host/ip. dir_only parameter is set to TRUE, returning "' + return_location + '" as the location.' );
    }

    else {

      return_location = location_target;

      if( debug || _http_debug ) display( 'DEBUG: Location header is pointing to "' + return_location + '" on the same host/ip. Returning this location.' );
    }

    return return_location;
  }
}

# @brief Extracts a HTTP cookie from a HTTP header.
#
# @param buf     The data to extract the cookie from.
# @param pattern The regex pattern to use for extracting the cookie. Defaults to "Set-Cookie\s*:\s*([^\r\n]+)".
#
# @return A string containing the extracted cookie or NULL if no cookie was found with the specified pattern
#         or if no buf parameter was passed.
#
function http_get_cookie_from_header( buf, pattern ) {

  local_var buf, pattern;
  local_var match;

  if( ! buf ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#buf#-#http_get_cookie_from_header" );
    return;
  }

  if( ! pattern )
    pattern = '[Ss]et-[Cc]ookie\\s*:\\s*([^\r\n]+)';

  if( match = eregmatch( pattern:pattern, string:buf ) )
    return match[ max_index( match ) -1 ];
  else
    return;
}

# @brief Creates a list of URLs from an array created by @ref http_get_kb_cgis and appends
#        the exploit request (passed via the ex parameter) to each of the URL parameter.
#
# @param cgiArray The list of URLs created by @ref http_get_kb_cgis.
# @param ex       The exploit request to append to each URL parameter.
#
# @return A list of URLs with the exploit request (passed via the ex parameter) appended to each of the
#         URL parameter or an empty list if no URL parameter was passed.
#
function http_create_exploit_req( cgiArray, ex ) {

  local_var cgiArray, ex;
  local_var urls, pseudocount, _rrayval, tmpf, data, param, z, url, i;

  urls = make_array();

  pseudocount = 0;
  foreach _rrayval( cgiArray ) {
    if( pseudocount >= 2 ) {
      if( "]" >< _rrayval ) {
        pseudocount--;
        tmpf = ereg_replace( pattern:"\[|\]", string:_rrayval, replace:"" );
        data[pseudocount] = tmpf;
      } else {
        param[pseudocount] = _rrayval;
      }
    } else {
      param[pseudocount] = _rrayval;
    }
    pseudocount++;
  }

  for( z = 2; z < max_index( param ); z++ ) {
    url = string( param[0], "?" );
    for( i = 2; i < max_index( param ); i++ ) {
      if( z == i ) {
        url += param[i] + "=" + ex;
      } else {
        if( data[i] ) {
          url += param[i] + "=" + data[i];
        } else {
          url += param[i] + "=";
        }
      }
      if( param[i + 1] ) {
        url += "&";
      }
    }
    urls = make_list( urls, url + "&" );
  }

  return urls;
}

# @brief Returns the Basic Authentication (Basic Auth) information from the passed data.
#
# @param data The data to extract the information from.
#
# @return An array containing the following index = value:
#
#         basic_auth = TRUE/FALSE if Basic Auth is available/found
#         realm      = A string containing the Basic Auth realm or "Undefined/Unknown" if none found
#
function http_extract_basic_auth( data ) {

  local_var data;
  local_var infos, header, realm;

  infos = make_array( "basic_auth", FALSE,
                      "realm", "Undefined/Unknown" );

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_extract_basic_auth" );
    return infos;
  }

  if( ! header = egrep( pattern:"^WWW-Authenticate\s*:\s*Basic", string:data, icase:TRUE ) )
    return infos;

  infos["basic_auth"] = TRUE;

  realm = eregmatch( pattern:"realm=(.*)", string:header, icase:TRUE );
  if( realm[1] )
    infos["realm"] = chomp( realm[1] );

  return infos;
}

# @brief Returns the info if a remote web server was internally (in the KB)
#        marked as "broken" by no404.nasl. It will also save the information
#        in an internal array to avoid that redis is queried again for the
#        same info.
#
# @param port The port of the remote server.
# @param host The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#             parameter or get_host_name) of the remote server. If no host parameter
#             is passed http_host_name will be called automatically and a debug
#             message is logged into the KB. A special "*" string can be passed
#             where the function will return TRUE if any of the remote hostnames
#             are marked as "broken".
#
# @return TRUE if the remote web server was marked as broken, FALSE otherwise and
#         NULL in the case where the port parameter wasn't passed.
#
function http_get_is_marked_broken( port, host ) {

  local_var port, host;
  local_var marked_broken_list, marked_broken, _mb;
  # nb: _http_is_broken_array is a global_var (see on top)

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_is_marked_broken" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_get_is_marked_broken" );
    host = http_host_name( dont_add_port:TRUE );
  }

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( _http_is_broken_array[host+port] ) ) {
    if( _http_is_broken_array[host+port] )
      return TRUE;
    else
      return FALSE;
  }

  if( host == "*" ) {
    marked_broken_list = get_kb_list( "www/*/" + port + "/is_broken" );
    if( ! marked_broken_list || typeof( marked_broken_list ) != "array" ) {
      marked_broken = FALSE;
    } else {
      foreach _mb( marked_broken_list ) {
        if( _mb ) {
          marked_broken = TRUE;
          break;
        }
      }
    }
  } else {
    marked_broken = get_kb_item( "www/" + host + "/" + port + "/is_broken" );
  }

  if( marked_broken ) {
    _http_is_broken_array[host+port] = TRUE;
  } else {
    _http_is_broken_array[host+port] = FALSE;
    marked_broken = FALSE;
  }

  return marked_broken;
}

# @brief Sets if a remote web server should be marked as "broken" to other VTs.
#        The status is set within the following KB entry:
#        "www/" + host + "/" + port + "/is_broken"
#
# @param port   The port of the remote server.
# @param host   The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#               parameter or get_host_name) of the remote server.
# @param reason The (optional) reason text why the remote web server was marked
#               as "broken" (saved as "www/" + host + "/" + port + "/broken/reason").
#
# @return TRUE if the status was successfully saved within the KB and
#         NULL if no port or host parameter was passed.
#
function http_set_is_marked_broken( port, host, reason ) {

  local_var port, host, reason;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_set_is_marked_broken" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_set_is_marked_broken" );
    return NULL;
  }

  if( strlen( reason ) > 0 )
    set_kb_item( name:"www/" + host + "/" + port + "/broken/reason", value:reason );

  set_kb_item( name:"www/" + host + "/" + port + "/is_broken", value:TRUE );
  _http_is_broken_array[host+port] = TRUE;
  return TRUE;
}

# @brief Returns all files identified on a remote web page and which are saved in
#        the knowledge base (by e.g. webmirror.nasl) within the following KB tree:
#        "www/" + host + "/" + port + "/content/extensions/".
#
# @param port The port of the remote server for which the detected files should
#             be returned. This parameter is optional and if not passed the
#             files of all web servers on the remote host are returned.
# @param host The hostname of the remote server (e.g. from http_host_name with the
#             dont_add_port:TRUE parameter or get_host_name) for which the detected
#             files should be returned. This parameter is optional and if not passed
#             the files of all web servers and all hostnames of the remote host are
#             returned.
# @param ext  The file extension for which the detected files should be returned.
#             A "php" passed to this parameter would e.g. return /index.php
#             and /index2.php. A wildcard like "php*" could be used as well which
#             would return /index.php and /index.php5. Similar a full wildcard like
#             "*" can be passed as well which would return all detected files. This
#             parameter is optional and if not passed the files of all web servers
#             and all hostnames of the remote host are returned.
#
# @return A list of files matching the specified parameters, NULL in the case no files
#         have matched the parameters or none have been identified at all.
#
# @note Add a dependency to at least DDI_Directory_Scanner.nasl and webmirror.nasl
#       when using this function within a VT.
#
function http_get_kb_file_extensions( port, host, ext ) {

  local_var port, host, ext;
  local_var list, _item;

  if( ! port )
    port = "*";

  if( ! host )
    host = "*";

  if( ! ext  )
    ext  = "*";

  list = get_kb_list( "www/" + host + "/" + port + "/content/extensions/" + ext );
  if( ! list || typeof( list ) != "array" )
    return NULL;

  if( max_index( list ) == 0 ) {
    foreach _item( list )
      return list;

    return NULL;
  }

  return list;
}

# @brief Returns all files/directories requiring authentication on a remote web page and
#        which are saved in the knowledge base (by e.g. webmirror.nasl) within the following
#        KB tree: "www/" + host + "/" + port + "/content/auth_required".
#
# @param port The port of the remote server for which the detected files/directories
#             should be returned. This parameter is optional and if not passed the
#             files/directories of all web servers on the remote host are returned.
# @param host The hostname of the remote server (e.g. from http_host_name with the
#             dont_add_port:TRUE parameter or get_host_name) for which the detected
#             files/directories should be returned. This parameter is optional and if
#             not passed the files/directories of all web servers and all hostnames
#             of the remote host are returned.
#
# @return A list of files/directories requiring authentication, NULL in the case no files/
#         directories have matched the parameters or none have been identified at all.
#
# @note Add a dependency to at least DDI_Directory_Scanner.nasl and webmirror.nasl
#       when using this function within a VT.
#
function http_get_kb_auth_required( port, host ) {

  local_var port, host;
  local_var list, _item;

  if( ! port )
    port = "*";

  if( ! host )
    host = "*";

  list = get_kb_list( "www/" + host + "/" + port + "/content/auth_required" );
  if( ! list || typeof( list ) != "array" )
    return NULL;

  if( max_index( list ) == 0 ) {
    foreach _item( list )
      return list;

    return NULL;
  }

  return list;
}

# @brief Returns all CGIs (namely scripts with a parameter) on a remote web page and which
#        are saved in the knowledge base (by e.g. webmirror.nasl) within the following KB
#        tree: "www/" + host + "/" + port + "/content/cgis/plain_cgis".
#        The returned syntax is the following:
#        /url - var [] -> This would match http://example.com/url?var=
#        /url - var [param] -> This would match http://example.com/url?var=param
#        /url - var1 [param1] var2 [param2] var3 [param3] -> This would match http://example.com/url?var1=param1&var2=param2&var3=param3
#
# @param port The port of the remote server for which the detected CGIs should be returned.
#             This parameter is optional and if not passed the CGIs of all web servers on
#             the remote host are returned.
# @param host The hostname of the remote server (e.g. from @ref http_host_name with the
#             dont_add_port:TRUE parameter or @ref get_host_name) for which the detected
#             CGIs should be returned. This parameter is optional and if not passed the
#             CGIs of all web servers and all hostnames of the remote host are returned.
#
# @return A list of CGIs in the syntax shown in the function description, NULL in the case
#         no CGIs have matched the parameters or none have been identified at all.
#
# @note Add a dependency to at least DDI_Directory_Scanner.nasl and webmirror.nasl when
#       using this function within a VT.
#
function http_get_kb_cgis( port, host ) {

  local_var port, host;
  local_var list, _item;

  if( ! port )
    port = "*";

  if( ! host )
    host = "*";

  list = get_kb_list( "www/" + host + "/" + port + "/content/cgis/plain_cgis" );
  if( ! list || typeof( list ) != "array" )
    return NULL;

  if( max_index( list ) == 0 ) {
    foreach _item( list )
      return list;

    return NULL;
  }

  return list;
}

# @brief Returns all CGIs (namely scripts with a parameter) on a remote web page and which
#        are saved in the knowledge base (by e.g. webmirror.nasl) within the following KB
#        tree: "www/" + host + "/" + port + "/content/cgis/full_cgis".
#        The returned syntax is the following:
#        /url?var -> This would match http://example.com/url?var=
#        /url?var=param -> This would match http://example.com/url?var=param
#        /url?var1=param1&var2=param2&var3=param3 -> This would match
#          http://example.com/url?var1=param1&var2=param2&var3=param3
#
# @param port The port of the remote server for which the detected CGIs should be returned.
#             This parameter is optional and if not passed the CGIs of all web servers on
#             the remote host are returned.
# @param host The hostname of the remote server (e.g. from @ref http_host_name with the
#             dont_add_port:TRUE parameter or @ref get_host_name) for which the detected
#             CGIs should be returned. This parameter is optional and if not passed the
#             CGIs of all web servers and all hostnames of the remote host are returned.
#
# @return A list of CGIs in the syntax shown in the function description, NULL in the case
#         no CGIs have matched the parameters or none have been identified at all.
#
# @note Add a dependency to at least DDI_Directory_Scanner.nasl and webmirror.nasl when
#       using this function within a VT.
#
function http_get_kb_cgis_full( port, host ) {

  local_var port, host;
  local_var list, _item;

  if( ! port )
    port = "*";

  if( ! host )
    host = "*";

  list = get_kb_list( "www/" + host + "/" + port + "/content/cgis/full_cgis" );
  if( ! list || typeof( list ) != "array" )
    return NULL;

  if( max_index( list ) == 0 ) {
    foreach _item( list )
      return list;

    return NULL;
  }

  return list;
}

# @brief Checks if a specific passed data contains a 200 HTTP status code.
#        If no such status code was identified the KB is checked additionally
#        (by using @ref http_get_no404_string) if the remote web server is
#        responding with a 200 HTTP status code to a non-existent file/url.
#
# @param port The port of the remote server.
# @param host The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#             parameter or get_host_name) of the remote server.
# @param data The data which is checked in form of a HTTP response.
#
# @return TRUE if the passed data contains a 200 HTTP status code or a string
#         as described in @ref http_get_no404_string was identified by no404.nasl,
#         FALSE otherwise and NULL if no port, host or data parameter was passed
#         or the data parameter doesn't contain a valid HTTP response.
#
# @todo See the todo for @ref http_get_no404_string above.
#
function http_data_has_200( port, host, data ) {

  local_var port, host, data;
  local_var no404;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_data_has_200" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_data_has_200" );
    return NULL;
  }

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_data_has_200" );
    return NULL;
  }

  if( ! ereg( string:data, pattern:"^HTTP/1\.[01] +[0-9]+" ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_data_has_200(): No data containing a valid HTTP status code passed in data variable." );
    return NULL;
  }

  if( ereg( string:data, pattern:"^HTTP/1\.[01] +200" ) ) {
    no404 = http_get_no404_string( port:port, host:host );
    if( ! no404 || no404 >!< data )
      return TRUE;
  }

  return FALSE;
}

# @brief Creates and returns report containing the URL to a "vulnerable" location on the
#        remote web server.
#
# @param port     The port of the remote server.
# @param url      The URL to the "vulnerable" location which should be included in the report
# @param url_only If set to TRUE the "Vulnerable url:" text won't be added to the report
#                 and only the plain URL is returned within the report.
#
# @return A string containing the generated report or NULL if no port or url parameter
#         was passed.
#
function http_report_vuln_url( port, url, url_only ) {

  local_var port, url, url_only;
  local_var proto, host, report;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_report_vuln_url" );
    return NULL;
  }

  if( ! url ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#http_report_vuln_url" );
    return NULL;
  }

  proto = "http";
  if( get_port_transport( port ) > ENCAPS_IP )
    proto = "https";

  host = http_host_name( port:port );

  if( url_only ) {
    report = proto + "://" + host + url;
  } else {
    report = "Vulnerable URL: " + proto + "://" + host + url;
  }
  return report;
}

# @brief Crafts a raw HTTP POST/PUT request (without sending it to the target) and returns it as a string.
#
# @param port               The port of the remote server.
# @param url                The URL to request, if not passed "/" will be used.
# @param data               The data which needs to be added in the body of the HTTP POST/PUT request.
# @param add_headers        Additional headers which should be added to the HTTP POST/PUT request. Needs to be an
#                           array in form of e.g. make_array( "Content-Type", "application/x-www-form-urlencoded" )
# @param accept_header      The Accept: header to use (e.g. application/json), defaults to "*/*" if not passed.
# @param accept_encoding    The Accept-Encoding: header to use (e.g. gzip, deflate), defaults to "identity" if not passed.
# @param user_agent         The User-Agent to use within the User-Agent: header, defaults to the result of the
#                           http_get_user_agent() function if not passed. If this parameter is given the function
#                           will add a separate X-Scanner: header field by default. This behavior can be disabled
#                           via the dont_add_xscanner parameter set to TRUE.
# @param host_header_use_ip If set to TRUE the request will contain the IP instead of the target
#                           hostname in the Host: header. This can be used for special targets not
#                           accepting the hostname in the request.
# @param dont_add_xscanner  Can be used in conjunction with the user_agent parameter. If set to TRUE the function
#                           is not adding a separate X-Scanner: header field to the request.
# @param referer_url        A URL like "/test.html" from which the Referer like Referer: http://127.0.0.1/test.html is build from.
# @param method             The HTTP method to use. Currently supported: POST, PUT. Defaults to POST if not given.
#
# @return A string containing the raw HTTP POST/PUT request or NULL if no port parameter was passed or
#         the data passed in the add_headers parameter isn't an array.
#
# @example req = http_post_put_req( port:port, url:"/", data:data, accept_header:"application/json", add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
#
function http_post_put_req( port, url, data, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url, method ) {

  local_var port, url, data, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url, method;
  local_var x_header, len, vtstrings, x_scanner_string, host, req, proto, _header;

  if( ! isnull( add_headers ) ) {
    if( typeof( add_headers ) != "array" ) {
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#add_headers_no-array#-#http_post_put_req" );
      return;
    }
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_post_put_req" );
    return;
  }

  if( method && method !~ "^(POST|PUT)$" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_post_put_req(): Unsupported method '" + method + "' passed to the 'method' parameter (Currently supported: POST, PUT). Falling back to the default 'POST'." );
    method = "POST";
  }

  if( ! url )
    url = "/";

  x_header = FALSE;

  if( data )
    len = strlen( data );

  if( ! accept_header )
    accept_header = '*/*';

  if( ! accept_encoding )
    accept_encoding = 'identity';

  if ( ! user_agent ) {
    user_agent = http_get_user_agent();
  } else if( ! dont_add_xscanner ) {
    x_header = TRUE;
    vtstrings = get_vt_strings();
    if( OPENVAS_VERSION )
      x_scanner_string = "X-Scanner: " + vtstrings["default"] + " " + OPENVAS_VERSION;
    else
      x_scanner_string = "X-Scanner: " + vtstrings["default"];
  }

  if( host_header_use_ip )
    host = http_host_name( port:port, use_ip:TRUE );
  else
    host = http_host_name( port:port );

  if( method && method =~ "^(POST|PUT)$" )
    method = toupper( method );
  else
    method = "POST";

  req = method + ' ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Pragma: no-cache\r\n' +
        'User-Agent: ' + user_agent + '\r\n' +
        'Accept-Language: en\r\n' +
        'Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\r\n' +
        'Accept: ' + accept_header + '\r\n' +
        'Accept-Encoding: ' + accept_encoding + '\r\n';

  if( referer_url ) {
    proto  = "http";
    if( get_port_transport( port ) > ENCAPS_IP )
      proto = "https";
    req += 'Referer: ' + proto + '://' + host + referer_url + '\r\n';
  }

  if( data )
    req += 'Content-Length: ' + len + '\r\n';

  if( x_header )
    req += x_scanner_string + '\r\n';

  if( ! isnull( add_headers ) ) {
    foreach _header( keys( add_headers ) )
      req += _header + ': ' + add_headers[_header] + '\r\n';
  }

  req += '\r\n';

  if( data )
    req += data;

  return req;
}

# @brief Crafts a raw HTTP GET request (without sending it to the target) and returns it as a string.
#
# @param port               The port of the remote server.
# @param url                The URL to request, if not passed "/" will be used.
# @param add_headers        Additional headers which should be added to the HTTP GET request. Needs to be an
#                           array in form of e.g. make_array( "Cookie", "PHPSESSID=" + sessid )
# @param accept_header      The Accept: header to use (e.g. text/html), defaults to the following if not passed:
#                           image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*
# @param accept_encoding    The Accept-Encoding: header to use (e.g. gzip, deflate). If empty no Accept-Encoding
#                           header is added.
# @param user_agent         The User-Agent to use within the User-Agent: header, defaults to the result of the
#                           http_get_user_agent() function if not passed. If this parameter is given the function
#                           will add a separate X-Scanner: header field by default. This behavior can be disabled
#                           via the dont_add_xscanner parameter set to TRUE.
# @param host_header_use_ip If set to TRUE the request will contain the IP instead of the target
#                           hostname in the Host: header. This can be used for special targets not
#                           accepting the hostname in the request.
# @param dont_add_xscanner  Can be used in conjunction with the user_agent parameter. If set to TRUE the function
#                           is not adding a separate X-Scanner: header field to the request.
# @param referer_url        A URL like "/test.html" from which the Referer like Referer: http://127.0.0.1/test.html is build from.
#
# @return A string containing the raw HTTP GET request or NULL if no port parameter was passed or
#         the data passed in the add_headers parameter isn't an array.
#
# @example req = http_get_req( port:port, url:"/", accept_header:"text/html", add_headers:make_array( "Cookie", "PHPSESSID=" + sessid ) );
#
function http_get_req( port, url, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url ) {

  local_var port, url, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url;
  local_var x_header, vtstrings, x_scanner_string, host, req, proto, _header;

  if( ! isnull( add_headers ) ) {
    if( typeof( add_headers ) != "array" ) {
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#add_headers_no-array#-#http_get_req" );
      return;
    }
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_req" );
    return;
  }

  if( ! url )
    url = "/";

  x_header = FALSE;

  if( ! accept_header )
    accept_header = 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*';

  if ( ! user_agent ) {
    user_agent = http_get_user_agent();
  } else if( ! dont_add_xscanner ) {
    x_header = TRUE;
    vtstrings = get_vt_strings();
    if( OPENVAS_VERSION )
      x_scanner_string = "X-Scanner: " + vtstrings["default"] + " " + OPENVAS_VERSION;
    else
      x_scanner_string = "X-Scanner: " + vtstrings["default"];
  }

  if( host_header_use_ip )
    host = http_host_name( port:port, use_ip:TRUE );
  else
    host = http_host_name( port:port );

  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'Connection: Close\r\n' +
        'Host: ' + host + '\r\n' +
        'Pragma: no-cache\r\n' +
        'Cache-Control: no-cache\r\n' +
        'User-Agent: ' + user_agent + '\r\n' +
        'Accept: ' + accept_header + '\r\n' +
        'Accept-Language: en\r\n' +
        'Accept-Charset: iso-8859-1,*,utf-8\r\n';

  if( referer_url ) {
    proto  = "http";
    if( get_port_transport( port ) > ENCAPS_IP )
      proto = "https";
    req += "Referer: " + proto + "://" + host + referer_url + '\r\n';
  }

  if( x_header )
    req += x_scanner_string + '\r\n';

  if( accept_encoding )
    req += "Accept-Encoding: " + accept_encoding + '\r\n';

  if( ! isnull( add_headers ) ) {
    foreach _header( keys( add_headers ) )
      req += _header + ": " + add_headers[_header] + '\r\n';
  }

  req += '\r\n';

  return req;
}

# @brief Returns the info if a "generic" XSS was found on the remote web server
#        to avoid that e.g. more than one VT is reporting the same XSS multiple
#        times. It will also save the information in an internal array to avoid
#        that redis is queried again for the same info.
#
# @param port The port of the remote server.
# @param host The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#             parameter or get_host_name) of the remote server. If no host parameter
#             is passed http_host_name will be called automatically and a debug
#             message is logged into the KB. A special "*" string can be passed
#             where the function will return TRUE if a "generic" XSS was found on
#             any of the remote hostnames.
#
# @return TRUE if the remote web server has a "generic" XSS, FALSE otherwise and
#         NULL in the case where the port parameter wasn't passed.
#
function http_get_has_generic_xss( port, host ) {

  local_var port, host;
  local_var generic_xss_list, generic_xss, _gxss;
  # nb: _http_has_generic_xss_array is a global_var (see on top)

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_has_generic_xss" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_get_has_generic_xss" );
    host = http_host_name( dont_add_port:TRUE );
  }

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( _http_has_generic_xss_array[host+port] ) ) {
    if( _http_has_generic_xss_array[host+port] )
      return TRUE;
    else
      return FALSE;
  }

  if( host == "*" ) {
    generic_xss_list = get_kb_list( "www/*/" + port + "/generic_xss" );
    if( ! generic_xss_list || typeof( generic_xss_list ) != "array" ) {
      generic_xss = FALSE;
    } else {
      foreach _gxss( generic_xss_list ) {
        if( _gxss ) {
          generic_xss = TRUE;
          break;
        }
      }
    }
  } else {
    generic_xss = get_kb_item( "www/" + host + "/" + port + "/generic_xss" );
  }

  if( generic_xss )
    _http_has_generic_xss_array[host+port] = TRUE;
  else
    _http_has_generic_xss_array[host+port] = FALSE;

  return generic_xss;
}

# @brief Sets the info if a "generic" XSS was found on the remote web server to
#        avoid that e.g. more than one VT is reporting the same XSS multiple
#        times. The status is set within the following KB entry:
#        "www/" + host + "/" + port + "/generic_xss"
#
# @param port The port of the remote server
# @param host The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#             parameter or get_host_name) of the remote server.
#
# @return TRUE if the status was successfully saved within the KB and
#         NULL if no port or host parameter was passed.
#
# @todo Maybe also save the "location" of the generic XSS?
#
function http_set_has_generic_xss( port, host ) {

  local_var port, host;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_set_has_generic_xss" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_set_has_generic_xss" );
    return NULL;
  }

  set_kb_item( name:"www/" + host + "/" + port + "/generic_xss", value:TRUE );
  return TRUE;
}

# @brief Returns the info if "CGI Scanning" was disabled (Settings/disable_cgi_scanning of global_settings.nasl) within the
#        scan config. To avoid querying the KB for the same info again it will be cached within an internal variable.
#
# @return TRUE if CGI scanning is disabled, FALSE otherwise.
#
function http_is_cgi_scan_disabled() {

  local_var is_cgi_scan_disabled;
  # nb: __http_is_cgi_scan_disabled is a global var

  if( ! isnull( __http_is_cgi_scan_disabled ) ) {
    is_cgi_scan_disabled = __http_is_cgi_scan_disabled;
  } else {
    is_cgi_scan_disabled = get_kb_item( "Settings/disable_cgi_scanning" );
    if( is_cgi_scan_disabled )
      __http_is_cgi_scan_disabled = TRUE;
    else
      __http_is_cgi_scan_disabled = FALSE;
    is_cgi_scan_disabled = __http_is_cgi_scan_disabled;
  }
  return is_cgi_scan_disabled;
}

# @brief Extracts the body of a full (including headers) HTTP response.
#
# @param data The HTTP response to extract the body from.
#
# @return The extracted HTTP body from the passed data, the whole passed data if it has missed HTTP
#         headers / included malformed HTTP headers or NULL if no data was passed or no HTTP body
#         was included in the passed data.
#
function http_extract_body_from_response( data ) {

  local_var data;
  local_var pattern, split;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_extract_body_from_response" );
    return NULL;
  }

  if( data !~ "^HTTP/1\.[01] [0-9]{3}" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_extract_body_from_response(): Invalid data not containing HTTP headers passed." );
    return data;
  }

  pattern = '\r\n\r\n#######header#######body#######split#######';
  data = str_replace( string:data, find:'\r\n\r\n', replace:pattern, count:1 );
  if( pattern >!< data )
    return data;

  split = split( data, sep:pattern, keep:FALSE );
  # nb: If there was e.g. no body in the passed data.
  if( ! split[1] )
    return NULL;
  else
    return split[1];
}

# @brief Extracts the headers of a full (including body) HTTP response.
#
# @param data The HTTP response to extract the headers from.
#
# @return The extracted HTTP headers from the passed data, the whole passed data if it has missed
#         HTTP headers / included malformed HTTP headers or NULL if no data was passed at all.
#
function http_extract_headers_from_response( data ) {

  local_var data;
  local_var pattern, split;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_extract_headers_from_response" );
    return NULL;
  }

  if( data !~ "^HTTP/1\.[01] [0-9]{3}" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_extract_headers_from_response(): Invalid data not containing HTTP headers passed." );
    return data;
  }

  pattern = '\r\n\r\n#######header#######body#######split#######';
  data = str_replace( string:data, find:'\r\n\r\n', replace:pattern, count:1 );
  if( pattern >!< data )
    return data;

  split = split( data, sep:pattern, keep:FALSE );
  # nb: Normally shouldn't be empty but we're checking it anyway just to be sure.
  if( ! split[0] )
    return NULL;
  else
    return split[0];
}

# @brief Returns the info if the "Caching of web pages during CGI scanning" option was disabled
#        (global_settings/disable_http_caching of global_settings.nasl) within the scan config.
#
# @note To avoid querying the KB for the same info again it will be cached within an internal
#       variable.
#
# @return TRUE if caching is disabled, FALSE otherwise.
#
function http_is_kb_caching_disabled() {

  local_var is_kb_caching_disabled;
  # nb: __http_is_kb_caching_disabled is a global var

  if( ! isnull( __http_is_kb_caching_disabled ) ) {
    is_kb_caching_disabled = __http_is_kb_caching_disabled;
  } else {
    is_kb_caching_disabled = get_kb_item( "global_settings/disable_http_kb_caching" );
    if( is_kb_caching_disabled )
      __http_is_kb_caching_disabled = TRUE;
    else
      __http_is_kb_caching_disabled = FALSE;
    is_kb_caching_disabled = __http_is_kb_caching_disabled;
  }
  return is_kb_caching_disabled;
}

# @brief Checks if a given HTTP response includes the HTML output of a phpinfo() PHP function call.
#
# @param data The HTTP response to be checked
# @param webmirror_called Internal parameter only, will be set by webmirror.nasl
#
# @note More info is available at https://www.php.net/manual/en/function.phpinfo.php
#
# @note This function isn't checking for the HTTP status code (e.g. 200) because that status code
#       might depend how the phpinfo() is called by the VT in question. Thus the calling VT should
#       check the status code instead.
#
# @return A string including all matching parts, FALSE if no phpinfo() output has been identified in
#         the response and NULL if no data has been passed.
#
function http_check_for_phpinfo_output( data, webmirror_called ) {

  local_var data, webmirror_called;
  local_var pattern, found, split_info, info, report;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_check_for_phpinfo_output" );
    return NULL;
  }

  pattern = "(";

  # Usually just:
  #
  # <title>phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
  #
  # but since PHP 7.3.0 (see https://www.php.net/ChangeLog-7.php#7.3.0) the version could be now
  # included as well:
  #
  # <title>PHP 7.3.0 - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
  # <title>PHP 7.4.3-4ubuntu2.18 - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
  # <title>PHP 8.2.12 - phpinfo()</title>
  #
  pattern += "<title>(PHP[^<]+)?phpinfo\(\)</title>|";

  # The availability of the following depends on how the "phpinfo()" function is called:
  #
  # - phpinfo(); -> Defaults to INFO_ALL and includes all info
  # - phpinfo(INFO_ENVIRONMENT); -> Only includes the Environment Variable information
  #
  # e.g.:
  #
  # <tr><td class="e">Configuration File (php.ini) Path </td><td class="v">/www/server/php/73/etc </td></tr>
  pattern += ">Configuration File \(php\.ini\) Path\s*<|";
  #
  # or:
  #
  # <h2>PHP Variables</h2>
  pattern += "<h2>PHP Variables</h2>";

  pattern += ")";

  # nb: The relevant code in webmirror.nasl seems to strip newlines so we need to re-add them after
  # each </$something> so that the report doesn't "explode".
  if( webmirror_called )
    data = ereg_replace( string:data, pattern:"(</[^>]+>)", replace:"\1" + '\n' );

  if( found = egrep( string:data, pattern:pattern, icase:FALSE ) ) {

    split_info = split( found, keep:FALSE );

    foreach info( split_info ) {
      if( report )
        report += '\n';

      info = ereg_replace( string:info, pattern:"^(\s+)", replace:"" );
      report += "  " + chomp( info );
    }

    return report;
  } else {
    return FALSE;
  }
}

# @brief Returns the info if the "Include OID in the User Agent within HTTP requests of various VTs
#        for debugging purposes" option was enabled (global_settings/http_ua_include_oid of
#        global_settings.nasl) within the scan config.
#
# @note To avoid querying the KB for the same info again it will be cached within an internal
#       variable.
#
# @note This enables to include the OID of the VT within the HTTP user agent of http_get_user_agent()
#       and http_send_recv() for debugging purposes on the target / targets logfiles.
#
# @return TRUE if the option was enabled, FALSE otherwise.
#
function http_ua_include_oid() {

  local_var ua_include_oid;
  # nb: __http_ua_include_oid is a global var

  if( ! isnull( __http_ua_include_oid ) ) {
    ua_include_oid = __http_ua_include_oid;
  } else {
    ua_include_oid = get_kb_item( "global_settings/http_ua_include_oid" );
    if( ua_include_oid )
      __http_ua_include_oid = TRUE;
    else
      __http_ua_include_oid = FALSE;
    ua_include_oid = __http_ua_include_oid;
  }
  return ua_include_oid;
}
