# SPDX-FileCopyrightText: 2005 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Note that the file "http_func.inc" must also be included when
# using this file.

global_var __ka_port, __ka_sockets,__ka_last_request, __ka_enabled_status;

__ka_port = 0;

# Saves / holds the "keepalive" socket for a specific host and port.
# Syntax/content is: array key -> host#--#port, array value: socket value (as an int)
__ka_sockets = make_array();

# Saves / holds the last request for a specific host and port
# Syntax/content is: array key -> host#--#port, array value: last request
__ka_last_request = make_array();

# Saves the "Keep alive" enabled status for a specific host and port
# Syntax/content is: array key -> host#--#port, array value: status (1 = KA enabled, 0 = KA disabled, -1 = connection error / unknown status)
__ka_enabled_status = make_array();

# Enables debugging output for a few functions below
global_var _http_ka_debug;
_http_ka_debug = FALSE;

# Global var passed to a few functions below
global_var optimize_test_enabled;
optimize_test_enabled = get_preference( "optimize_test" );

# @brief Determined on the passed header if the keep-alive socket of the
#        connection needs to be close and re-opened.
#
# @param headers The headers to evaluate.
# @param port    The HTTP port of the target.
# @param host    The HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#                or from get_host_name) of the remote target.
#
# @return NULL
#
function http_keepalive_check_connection( headers, host, port ) {

  local_var headers, host, port;

  if( ! headers ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#headers#-#http_keepalive_check_connection" );
    return NULL;
  }

  if( egrep( pattern:"^Connection\s*:\s*Close", string:headers, icase:TRUE ) )
    http_keepalive_reopen_connection( host:host, port:port );

  return NULL;
}

# @brief Opens a new socket to the specified port and sets it
#        internallly as the port/socket to be used for keep-alive connections.
#
# @param port The port to open a connection to.
# @param host The HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#             or from get_host_name) of the remote target.
#
# @return NULL
#
function http_enable_keepalive( port, host ) {

  local_var port, host;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_enable_keepalive" );
    return NULL;
  }

  if( ! host ) {
    host = http_host_name( dont_add_port:TRUE );
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_enable_keepalive" );
  }

  __ka_enabled_status[host + "#--#" + port] = 1;
  __ka_port = port;
  __ka_sockets[host + "#--#" + port] = http_open_socket( port );
  return NULL;
}

# @brief Determine if the remote web server is keep-alive enabled or not.
#
# @param port The HTTP port of the target.
# @param host The HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#             or from get_host_name) of the remote target.
#
# @return 1 if keep alive is enabled, 0 otherwise and -1 if no port was passed or no socket could be opened to the target host.
#
function http_keepalive_enabled( port, host ) {

  local_var port, host;
  local_var key, kb, useragent, host, soc, req, r;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_keepalive_enabled" );
    return -1;
  }

  if( ! host ) {
    host = http_host_name( dont_add_port:TRUE );
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_keepalive_enabled" );
  }

  key = strcat( "www/", host, "/", port, "/keepalive" );
  kb = get_kb_item( key );
  if( kb == "yes" ) {
    http_enable_keepalive( port:port, host:host );
    return( 1 );
  } else if( kb == "no" ) {
    return( 0 );
  }

  useragent = http_get_user_agent();

  # nb: Always keep http_host_name() before http_open_socket() as the first
  # could fork with multiple vhosts and the child's would share the same
  # socket causing race conditions and similar.
  # nb: Overwriting the previous declared host is expected as the Host: header
  # needs to include the port.
  host = http_host_name( port:port );

  soc = http_open_socket( port );
  if( ! soc )
    return -1;

  req = strcat( 'GET / HTTP/1.1\r\n',
                'Connection: Keep-Alive\r\n',
                'Host: ', host, '\r\n',
                'Pragma: no-cache\r\n',
                'User-Agent: ', useragent, '\r\n\r\n' );

  send( socket:soc, data:req );
  r = http_recv( socket:soc );

  # Apache
  if( egrep( pattern:"^Keep-Alive\s*:.*", string:r, icase:TRUE ) ) {
    http_close_socket( soc );
    set_kb_item( name:key, value:"yes" );
    http_enable_keepalive( port:port, host:host );
    return( 1 );
  } else {
    # IIS
    send( socket:soc, data:req );
    r = http_recv( socket:soc );
    http_close_socket( soc );
    if( strlen( r ) ) {
      set_kb_item( name:key, value:"yes" );
      http_enable_keepalive( port:port, host:host );
      return( 1 );
    }
  }
  set_kb_item( name:key, value:"no" );
  return( 0 );
}

# @brief This function is akin to @ref http_recv_body except that if the last request was
#        a HEAD, we bail out (whereas @ref http_recv will timeout).
#
# @param headers A (mandatory) previously received header used for evaluation within
#                this function.
# @param port The port of the remote server to connect to.
# @param host The (optional) HTTP hostname (e.g. from @ref http_host_name with the
#             "dont_add_port:TRUE" parameter or from @href get_host_name) of the remote
#             target. Defaults to all known hostnames if not passed.
# @param bodyonly If set to TRUE only the HTTP body will be returned.
# @param fetch404 If set to TRUE the function will also return the body of HTTP 404
#                 error pages.
# @param content_type_body_only Allows to fetch pages with e.g. only
#                               "Content-Type: text/html" by passing a regex like
#                               "^Content-Type\s*:\s*text/(xml|html)"
# @param headersonly If set to TRUE only the HTTP header will be returned.
#
# @note While this function is called @http_keepalive_recv_body it not only returns the
#       body of the received data but also the previously passed header (if bodyonly isn't
#       set to "TRUE").
#
# @return The received data (depending on the passed function parameter) as a string.
#
function http_keepalive_recv_body( headers, port, host, bodyonly, fetch404, content_type_body_only, headersonly ) {

  local_var headers, port, host, bodyonly, fetch404, content_type_body_only, headersonly;
  local_var close_connection, length, max_length_to_receive, tmp, gzip, body;
  # nb: _http_ka_debug, __ka_port, __ka_last_request and __ka_sockets are global vars

  if( ! headers ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#headers#-#http_keepalive_recv_body" );
    return( headers );
  }

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( ! port )
    port = __ka_port;

  # If the headers are not HTTP compliant, just return right away.
  if( ! ereg( pattern:"^HTTP/.* [0-9]{3}", string:headers ) ) {
    http_keepalive_reopen_connection( host:host, port:port );
    return( headers );
  }

  if( ereg( pattern:"^HEAD.*HTTP/.*", string:__ka_last_request[host + "#--#" + port] ) ) {

    http_keepalive_check_connection( headers:headers, host:host, port:port );

    if( headersonly )
      return( headers );

    # HEAD does not return a body
    if( bodyonly ) {
      return( "" );
    } else {
      return( headers );
    }
  }

  close_connection = FALSE;
  length = -1;
  # nb: Don't receive more than 1 MB in various parts of the code below (e.g. for systems
  # not providing a Content-Length header).
  max_length_to_receive = 1048576;

  if( egrep( pattern:"^Content-Length\s*:", string:headers, icase:TRUE ) ) {
    tmp = egrep( string:headers, pattern:"^Content-Length\s*:\s*[0-9]+", icase:TRUE );
    if( tmp )
      length = int( ereg_replace( string:tmp, pattern:"^Content-Length\s*:\s*([0-9]+).*", replace:"\1", icase:TRUE ) );
  }

  if( egrep( pattern:"^Content-Encoding\s*:\s*gzip", string:headers, icase:TRUE ) )
    gzip = TRUE;

  if( ( length < 0 ) && ( egrep( pattern:"^Transfer-Encoding\s*:\s*chunked", string:headers, icase:TRUE ) ) ) {
    while( 1 ) {
      tmp = recv_line( socket:__ka_sockets[host + "#--#" + port], length:4096 );
      if( ! tmp )
        length = 0;
      else
        length = hex2dec( xvalue:tmp );

      if( length > max_length_to_receive ) {
        length = max_length_to_receive;
        close_connection = TRUE; # nb: See the note on closing the connection below.
      }

      body = strcat( body, recv( socket:__ka_sockets[host + "#--#" + port], length:length, min:length ) );
      # "\r\n"
      recv( socket:__ka_sockets[host + "#--#" + port], length:2, min:2 );
      if( strlen( body ) > max_length_to_receive )
        close_connection = TRUE; # nb: See the note on closing the connection below.

      if( length == 0 || close_connection ) {

        # nb: If we have reached the 1MB limit defined above the server might still want
        # to send data to the current open socket. Because of this we need to close the
        # socket / connection to make sure the next request won't mix up the replies. The
        # call to http_keepalive_check_connection() is unnecessary in this case because
        # we're closing the socket anyway. This needs to be before all "return" calls below.
        if( close_connection )
          http_keepalive_reopen_connection( host:host, port:port );
        else
          http_keepalive_check_connection( headers:headers, host:host, port:port );

        if( headersonly )
          return( headers );

        # Only return the body of 404 pages if it was explicitly asked.
        if( ereg( pattern:"^HTTP/.* 404", string:headers ) && fetch404 != TRUE )
          return( headers );

        if( content_type_body_only ) {
          if( egrep( pattern:"^Content-Type\s*:", string:headers, icase:TRUE ) ) {
            if( ! egrep( pattern:content_type_body_only, string:headers, icase:TRUE ) )
              return( headers );
          }
        }

        # This is expected - don't put this line before the previous
        if( gzip && body )
          body = http_gunzip( buf:body, onlybody:TRUE );

        if( bodyonly ) {
          return( body );
        } else {
          return( strcat( headers, '\r\n', body ) );
        }
      }
    }
  }

  if( length >= 0 ) {

    if( length > max_length_to_receive )
      length = max_length_to_receive;

    body = recv( socket:__ka_sockets[host + "#--#" + port], length:length, min:length );
    if( body && strlen( body ) == max_length_to_receive )
      close_connection = TRUE; # nb: See the note on closing the connection below.

  } else {
    if( _http_ka_debug ) display( "DEBUG: ERROR - Keep Alive, but no length!!!\n", __ka_last_request[host + "#--#" + port] );
    body = recv( socket:__ka_sockets[host + "#--#" + port], length:16384, min:0 );

    # nb: For the case we have received a part of the page (note the length 16384 above).
    if( body =~ "<html[^>]*>" && body !~ "</html>" ) { # case insensitive
      repeat {
        tmp = recv( socket:__ka_sockets[host + "#--#" + port], length:16384 );
        body += tmp;
      }
      until( ! tmp || body =~ "</html>" );
      if( _http_ka_debug && body !~ "</html>" ) display( "DEBUG: http_keepalive_recv_body: incomplete body?\n------------\n", body, "\n------------\n" );
    }

    # nb: For the case we haven't received a valid HTML page at all.
    else if( body !~ "<html[^>]*>" || body !~ "</html>" ) { # case insensitive
      close_connection = TRUE; # nb: See the note on closing the connection below.
    }
  }

  # nb: If we have reached the 1MB limit defined above or if we don't have the length
  # (e.g. via the Content-Length header) the server might still want to send data to the
  # current open socket. Because of this we need to close the socket / connection to make
  # sure the next request won't mix up the replies. The call to
  # http_keepalive_check_connection() is unnecessary in this case because we're closing
  # we're closing the socket anyway. This needs to be before all "return" calls below.
  if( close_connection )
    http_keepalive_reopen_connection( host:host, port:port );
  else
    http_keepalive_check_connection( headers:headers, host:host, port:port );

  if( headersonly )
    return( headers );

  # Only return the body of 404 pages if it was explicitly asked.
  if( ereg( pattern:"^HTTP/.* 404", string:headers ) && fetch404 != TRUE )
    return( headers );

  if( content_type_body_only ) {
    if( egrep( pattern:"^Content-Type\s*:", string:headers, icase:TRUE ) ) {
      if( ! egrep( pattern:content_type_body_only, string:headers, icase:TRUE ) )
        return( headers );
    }
  }

  if( gzip && body )
    body = http_gunzip( buf:body, onlybody:TRUE );

  if( bodyonly )
    return( body );
  else
    return( strcat( headers, '\r\n', body ) );
}

# @brief Closes the opened keep-alive socket(s) on exit.
#
# @return NULL
#
function on_exit() {

  local_var _socket_infos, socket_infos, host, port, socket_status;

  foreach _socket_infos( keys( __ka_sockets ) ) {

    socket_infos = split( _socket_infos, sep:"#--#", keep:FALSE );
    if( max_index( socket_infos ) != 2 )
      continue;

    host = socket_infos[0];
    port = socket_infos[1];
    socket_status = __ka_sockets[_socket_infos];

    if( socket_status ) {
      http_close_socket( __ka_sockets[_socket_infos] );
      __ka_sockets[_socket_infos] = 0;
    }
  }
  return NULL;
}

if( 0 ) on_exit(); #TBD: What's the purpose of this?

# @brief This is our "public" Keep-Alive function. It sends <data> to the remote host on
#        port <port>, and returns the result, or NULL if no connection could be
#        established.
#
# @param port The (mandatory) port of the remote server to connect to.
# @param data The (mandatory) data to sent to the remote server.
# @param host The (optional) HTTP hostname (e.g. from @ref http_host_name with the
#             "dont_add_port:TRUE" parameter or from @href get_host_name) of the remote
#             target. Defaults to all known hostnames if not passed.
# @param bodyonly If set to TRUE only the HTTP body will be returned.
# @param fetch404 If set to TRUE the function will also return the body of HTTP 404
#                 error pages.
# @param content_type_body_only Allows to fetch pages with e.g. only
#                               "Content-Type: text/html" by passing a regex like
#                               "^Content-Type\s*:\s*text/(xml|html)"
# @param headersonly If set to TRUE only the HTTP header will be returned.
#
# @return A string containing the received data or NULL if no connection could be
#         esablished or no port or data parameter was passed.
#
function http_keepalive_send_recv( port, data, host, bodyonly, fetch404, content_type_body_only, headersonly ) {

  local_var port, data, host, bodyonly, fetch404, content_type_body_only, headersonly;
  local_var oid, user_agent, oid_str, soc, headers, body, n, lendata;
  # nb: _http_ka_debug, __ka_enabled_status and __ka_sockets are global vars

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_keepalive_send_recv" );
    return NULL;
  }

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_keepalive_send_recv" );
    return NULL;
  }

  # nb: We should expect at least a request like: "GET / HTTP/1.1\r\n\r\n" (length: 18).
  # But for some specific cases we're just checking for some less data.
  if( strlen( data ) < 8 || data !~ "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL).*HTTP/(1\.[01]|2)" ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.900522" && # secpod_ziproxy_server_detect.nasl might require the wrong request to trigger the detection
        oid != "1.3.6.1.4.1.25623.1.0.11438"  && # pre2008/tomcat_directory_listing_and_file_disclosure.nasl is passing a raw_string(0) in the request which is something the "!~" above can't handle causing a false positive here.
        oid != "1.3.6.1.4.1.25623.1.0.10730" )   # pre2008/raptor_detect.nasl as well
      set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#http_keepalive_send_recv(): Invalid HTTP request (length < 8, invalid HTTP method or missing HTTP/ header) passed in 'data' variable." );
  }

  # http_get() won't add a Host: header if only HTTP/1.0 support was detected.
  # There are also no VTs sending HTTP 0.9 requests but still adding this here.
  if( "Host: " >!< data && " HTTP/1.0" >!< data && " HTTP/0.9" >!< data ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.802045" ) # nb: gb_linux_rootkit_nginx_iframe_injection.nasl requires a wrong host header
      set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#http_keepalive_send_recv(): No 'Host:' header passed in 'data' variable. This might lead to issues if SNI is enabled on the remote host." );
  }

  if( data !~ "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL) (/|\.+/|https?:|\*).* HTTP" ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.103293" && # gb_apache_49957.nasl requires sending a @localhost URI
        oid != "1.3.6.1.4.1.25623.1.0.17230"  && # cern_httpd_access_ctrl.nasl requires sending a \ at the start of the URI
        oid != "1.3.6.1.4.1.25623.1.0.900522" && # secpod_ziproxy_server_detect.nasl might require the wrong request to trigger the detection
        oid != "1.3.6.1.4.1.25623.1.0.11438"  && # pre2008/tomcat_directory_listing_and_file_disclosure.nasl is passing a raw_string(0) in the request which is something the "!~" above can't handle causing a false positive here.
        oid != "1.3.6.1.4.1.25623.1.0.10730" )   # pre2008/raptor_detect.nasl as well
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_keepalive_send_recv(): URL/URI of the HTTP request passed in 'data' variable doesn't start with one of the following: '/, ./, http, *'." );
  }

  # Some (mostly older) VTs are not passing the User-Agent header but we should always have one.
  if( " HTTP/1.1" >< data && ! egrep( pattern:"^User-Agent\s*:.+", string:data, icase:TRUE ) ) {
    oid = get_script_oid();
    if( oid != "1.3.6.1.4.1.25623.1.0.11438" ) { # pre2008/tomcat_directory_listing_and_file_disclosure.nasl is passing a raw_string(0) in the request which is something the egrep above can't handle. If that is happening the ereg_replace below is breaking the request then most likely for the same reason.
      data = ereg_replace( string:data, pattern:'\r\n\r\n', replace:'\r\nUser-Agent: ' + http_get_user_agent() + '\r\n\r\n' );
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_keepalive_send_recv(): Using a HTTP/1.1 request without a 'User-Agent:' header passed in 'data' variable. Adding it automatically to the request." );
    }
  }

  if( http_ua_include_oid() && user_agent = egrep( pattern:"^User-Agent:.+", string:data, icase:TRUE ) ) {
    user_agent = chomp( user_agent );
    oid_str = "(OID:" + get_script_oid() + ")";
    if( oid_str >!< user_agent )
      data = str_replace( string:data, find:user_agent, replace:user_agent + " " + oid_str );
  }

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( _http_ka_debug ) display( "DEBUG: http_keepalive_send_recv( host: ", host, ", port: ", port, ", data: ", data, ", bodyonly: ", bodyonly, " )\n" );

  if( isnull( __ka_enabled_status[host + "#--#" + port] ) )
    __ka_enabled_status[host + "#--#" + port] = http_keepalive_enabled( port:port, host:host );

  if( __ka_enabled_status[host + "#--#" + port] == -1 )
    return NULL;

  if( __ka_enabled_status[host + "#--#" + port] == 0 ) {
    soc = http_open_socket( port );
    if( ! soc )
      return NULL;

    if( send( socket:soc, data:data ) <= 0 ) {
      http_close_socket( soc );
      return NULL;
    }

    headers = http_recv_headers2( socket:soc );
    # If no headers received or the headers are not HTTP compliant, just return right away.
    if( ! headers || ! ereg( pattern:"^HTTP/.* [0-9]{3}", string:headers ) ) {
      http_close_socket( soc );
      return( headers );
    }

    if( headersonly ) {
      http_close_socket( soc );
      return( headers );
    }

    if( content_type_body_only ) {
      if( egrep( pattern:"^Content-Type\s*:", string:headers, icase:TRUE ) ) {
        if( ! egrep( pattern:content_type_body_only, string:headers, icase:TRUE ) ) {
          http_close_socket( soc );
          return( headers );
        }
      }
    }

    # Only return the body of 404 pages if it was explicitly asked.
    if( ereg( pattern:"^HTTP/.* 404", string:headers ) && fetch404 != TRUE ) {
      http_close_socket( soc );
      return( headers );
    }

    body = http_recv_body( socket:soc, headers:headers, length:0 );

    http_close_socket( soc );

    if( body && egrep( pattern:"^Content-Encoding\s*:\s*gzip", string:headers, icase:TRUE ) )
      body = http_gunzip( buf:body, onlybody:TRUE );

    if( bodyonly )
      return( body );
    else
      return( strcat( headers, '\r\n', body ) );
  }

  if( ( port != __ka_port ) || ( ! __ka_sockets[host + "#--#" + port] ) ) {
    http_keepalive_reopen_connection( host:host, port:port );
    if( ! __ka_sockets[host + "#--#" + port] )
      return NULL;
  }

  # Old behavior: data = str_replace( string:data, find:"Connection: Close", replace:"Connection: Keep-Alive", count:1 );
  # https://tools.ietf.org/html/rfc7230#section-6.1 -> Connection options are case-insensitive.
  # Some VT devs might add a "Connection: close" to the header data passed to this function so doing an ereg_replace instead
  # nb: Be aware that this ereg_replace is also replacing any occurrence of "Connection: Close" somewhere in the body of the request data.
  # TBD: Add a Connection: Keep-Alive if no Connection: Close is included in the passed request?
  data = ereg_replace( string:data, pattern:"Connection\s*:\s*Close", replace:"Connection: Keep-Alive", icase:TRUE );
  __ka_last_request[host + "#--#" + port] = data;
  n = send( socket:__ka_sockets[host + "#--#" + port], data:data );
  lendata = strlen( data );
  if( n >= lendata )
    headers = http_recv_headers2( socket:__ka_sockets[host + "#--#" + port] );

  if( ! headers ) {
    http_keepalive_reopen_connection( host:host, port:port );

    if( __ka_sockets[host + "#--#" + port] == 0 )
      return NULL;

    if( send( socket:__ka_sockets[host + "#--#" + port], data:data ) < lendata ) {
      http_close_socket( __ka_sockets[host + "#--#" + port] );
      __ka_sockets[host + "#--#" + port] = NULL;
      return NULL;
    }
    headers = http_recv_headers2( socket:__ka_sockets[host + "#--#" + port] );
  }

  # If no headers received, just return right away.
  if( ! headers )
    return( headers );

  # nb: Don't add any additional checks like e.g. HTTP response checks here and return on
  # them because http_keepalive_recv_body() needs to receive the full body. This needs to
  # be done done because we're not closing the socket (Keepalive connection) and if not
  # receiving the full response of the remote service it would be mixed up / received in
  # the next request.

  return http_keepalive_recv_body( headers:headers, bodyonly:bodyonly, fetch404:fetch404, content_type_body_only:content_type_body_only, headersonly:headersonly );
}

# @brief Creates a HTTP GET request with enabled Keep-Alive Connection for a
#        specified item (e.g. a script), sends the request to the target and checks
#        if the requested item is available.
#
# @param port The HTTP port of the target.
# @param item The item to request.
# @param host The (optional) HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#             or from get_host_name) of the remote target. Defaults to all known hostnames if not passed.
#
# @return TRUE if the requested item exists on the remote web server, FALSE otherwise
#         and NULL in the cases where wrong data is passed to the function or where the
#         server is respondig with a 200 status code to not existing files.
#
function http_is_cgi_installed_ka( port, item, host ) {

  local_var port, item, host;
  local_var dirs, slash, no404, _dir, req, res;
  # nb: optimize_test_enabled is a global var from above

  if( ! item ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#http_is_cgi_installed_ka" );
    return NULL;
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_is_cgi_installed_ka" );
    return NULL;
  }

  if( http_is_cgi_scan_disabled() ) {
    if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
      set_kb_item( name:"vt_debug_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#http_is_cgi_installed_ka()" );
    }
    exit( 0 );
  }

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( item[0] != "/" ) {
    dirs = http_cgi_dirs( port:port, host:host );
    slash = "/";
  } else {
    dirs = make_list("");
    slash = "";
  }

  no404 = http_get_no404_string( port:port, host:host );
  if( strlen( no404 ) >= 1 )
    return NULL;

  foreach _dir( dirs ) {

    if( _dir == "/" ) _dir = "";

    # some server return a 404 for / but sometimes not for all subdirs. so check again...
    req = http_get( item:_dir + slash + item + '_' + rand(), port:port );
    res = http_keepalive_send_recv( port:port, host:host, data:req );
    if( res !~ "^HTTP/1\.[01] 404" )
      continue;

    req = http_get( item:_dir + slash + item, port:port );
    res = http_keepalive_send_recv( port:port, host:host, data:req );
    if( ! res )
      continue;

    if( res =~ "^HTTP/1\.[01] +200 +" && res !~ "Proxy-Agent\s*:\s*IWSS" ) {
      if( no404 && tolower( no404 ) >< tolower( res ) ) {
        continue;
      } else {
        return TRUE;
      }
    }
  }
  return FALSE;
}

# @brief Creates an HTTP GET request for the specified URL, sends the request to the target
#        and receives the response. If a response was received it is saved into the knowledge
#        base. If an URL was requested which was requested previously the cached response
#        will be returned instead of doing a new request.
#
# @param port     The (mandatory) HTTP port of the target.
# @param item     The (mandatory) URL/item to request.
# @param host     The (optional) HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE
#                 parameter or from get_host_name) of the remote target. Defaults to all known
#                 hostnames if not passed.
# @param fetch404 If set to TRUE the function will also return the body of HTTP 404 error pages.
#
# @return The response to the HTTP GET request or NULL if no response was received or not
#         all required parameters got passed.
#
# @note The global_var __ka_last_request[host + "#--#" + port] can be used to access the "req"
#       crafted by this function.
#
# @note The caching of this function can be disabled in the scan config via "caching of web pages during CGI scanning"
#       (global_settings/disable_http_caching of global_settings.nasl). See @ref http_is_kb_caching_disabled.
#
function http_get_cache( port, item, host, fetch404 ) {

  local_var port, item, host, fetch404;
  local_var key, res, req;
  # nb: __ka_last_request is a global var
  # nb: optimize_test_enabled is a global var from above

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_cache" );
    return NULL;
  }

  if( ! item ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#item#-#http_get_cache" );
    return NULL;
  }

  if( http_is_cgi_scan_disabled() ) {
    if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
      set_kb_item( name:"vt_debug_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#http_get_cache()" );
    }
    exit( 0 );
  }

  if( fetch404 )
    key = "including_404_body";
  else
    key = "excluding_404_body";

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( ! http_is_kb_caching_disabled() ) {
    res = get_kb_item( "Cache/" + host + "/" + port + "/" + key + "/URL_" + item );
    if( res )
      return res;
  }

  req = http_get( port:port, item:item );
  __ka_last_request[host + "#--#" + port] = req;

  res = http_keepalive_send_recv( port:port, host:host, data:req, bodyonly:FALSE, fetch404:fetch404 );
  if( ! res || res !~ "^HTTP/1\.[01] [0-9]{3}" )
    return NULL;

  if( ! http_is_kb_caching_disabled() ) {

    # We only want so save responses not having the following HTTP status codes (which might
    # be just temporary) into our cache:
    # Internal Server Errors (5xx)
    # Too Many Requests (429)
    # Request Timeout (408)
    if( res !~ "^HTTP/1\.[01] (5(0[0-9]|1[01])|4(08|29))" )
      replace_kb_item( name:"Cache/" + host + "/" + port + "/" + key + "/URL_" + item, value:res );

  }
  return res;
}

# @brief Creates a HTTP GET request with enabled Keep-Alive Connection for a
#        specified item (e.g. a script), sends the request to the target and checks
#        if one or more specific patterns are included in the response. If the pattern
#        was found a security_message() is reported and the script exit afterwards.
#
# @param default_port  The default HTTP port to assume if no open ports was found on the target host.
# @param host          The (optional) HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#                      or from get_host_name) of the remote target. Defaults to all known hostnames if not passed.
# @param extra_dirs    Additional directories to check which are added to the found directories of @ref http_cgi_dirs. If empty only @ref http_cgi_dirs is used.
# @param unique_dir    The directory which should be checked, if this parameter is passed extra_dirs will be ignored.
# @param check_request The request / item to sent in the HTTP GET request.
# @param extra_check   A pattern to check additionally to the check_result in form of a regex.
# @param check_result  The expected result to the response in form of a regex where a security_message() is reported.
# @param command       The command which was used in the check_request parameter.
# @param port          The HTTP port to check.
#
# @return NULL
#
function http_check_remote_code( default_port, host, extra_dirs, unique_dir, check_request, extra_check, check_result, command, port ) {

  local_var default_port, host, extra_dirs, unique_dir, check_request, extra_check, check_result, command, port;
  local_var list, _dir, req, buf, txt_result, extra, txt_desc;
  # nb: optimize_test_enabled is a global var from above

  if( ! check_request ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#check_request#-#http_check_remote_code" );
    return NULL;
  }

  if( ! check_result ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#check_result#-#http_check_remote_code" );
    return NULL;
  }

  if( ! command )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#command#-#http_check_remote_code" );

  if( http_is_cgi_scan_disabled() ) {
    if( optimize_test_enabled && "yes" >< optimize_test_enabled ) {
      set_kb_item( name:"vt_debug_cgi_scanning_disabled/" + get_script_oid(), value:get_script_oid() + "#-#http_check_remote_code()" );
    }
    exit( 0 );
  }

  if( ! port ) {
    if( default_port ) {
      port = http_get_port( default:default_port );
    } else {
      port = http_get_port( default:80 );
    }
  } else {
    if( ! get_port_state( port ) )
      exit( 0 );
  }

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( unique_dir ) {
    list = make_list( unique_dir );
  } else {
    if( ! isnull( extra_dirs ) ) {
      list = make_list_unique( http_cgi_dirs( port:port, host:host ), extra_dirs );
    } else {
      list = make_list( http_cgi_dirs( port:port, host:host ) );
    }
  }

  foreach _dir( list ) {

    if( _dir == "/" ) _dir = "";

    req = string( _dir, check_request );
    req = http_get( item:req, port:port );
    buf = http_keepalive_send_recv( port:port, host:host, data:req );
    if( ! buf )
      continue;

    txt_result = egrep( pattern:check_result, string:buf );
    if( extra_check ) {
      extra = FALSE;
      if( egrep( pattern:extra_check, string:buf ) ) {
        extra = TRUE;
      }
    } else {
      extra = TRUE;
    }

    if( txt_result && extra ) {
      txt_desc = 'It was possible to execute the command "' + command + '" on the remote host, which produces the following output:\n\n' + txt_result;
      security_message( port:port, data:txt_desc );
      exit( 0 );
    }
  }
}

# @brief Checks a specific URL on the remote server if the response is matching / not matching the specified data.
#
# @param port          The HTTP port of the target.
# @param url           The URL/item to request.
# @param pattern       A regex pattern which needs to be included in the response of the target for the function to return TRUE.
# @param check_header  If set to TRUE the function is checking if it has received a HTTP 200 status code additionally to the regex pattern.
# @param debug         If set to TRUE the received data is displayed on the command line or in the scanners logfile.
# @param extra_check   A string or list containing extra pattern which needs to be included in the response. If multiple items are passed via
#                      a list all of these needs to be included in the response for the function to return TRUE.
# @param host          The (optional) HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#                      or from get_host_name) of the remote target. Defaults to all known hostnames if not passed.
# @param cookie        The cookie to send within the request.
#
# @param check_nomatch A string or list containing extra pattern which shouldn't be included in the response. If multiple items are passed via
#                      a list all of these shouldn't be included in the response for the function to return TRUE.
#
# @param icase         If set to TRUE (default if not passed) the pattern, extra_check and check_nomatch are evaluated case insensitive, otherwise if FALSE is passed.
# @param usecache      If set to TRUE the response will be cached within the internal Redis KB.
#
# @return TRUE If the requested data is matching / not matching the specified pattern, FALSE if not or no data was received and NULL if no url, port or pattern parameter was passed.
#
# @note The global_var __ka_last_request[host + "#--#" + port] can be used to access the "req" crafted by this VT.
#
function http_vuln_check( port, url, pattern, check_header, debug, extra_check, host, cookie, check_nomatch, icase, usecache ) {

  local_var port, url, pattern, check_header, debug, extra_check, host, cookie, check_nomatch, icase, usecache;
  local_var buf, req, _ec, _nm;
  # nb: __ka_last_request is a global var

  if( ! url ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#http_vuln_check" );
    return NULL;
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_vuln_check" );
    return NULL;
  }

  if( isnull( pattern ) || pattern == "" ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pattern#-#http_vuln_check" );
    return NULL;
  }

  if( isnull( icase ) )
    icase = TRUE;

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( usecache ) {
    buf = http_get_cache( item:url, port:port, host:host );
    if( cookie && ! isnull( cookie ) )
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_vuln_check(): Setting nocache to TRUE and passing a cookie isn't supported." );
  } else {

    req = http_get( item:url, port:port );

    if( cookie && ! isnull( cookie ) )
      req = ereg_replace( string:req, pattern:'\r\n\r\n', replace:'\r\nCookie: ' + cookie + '\r\n\r\n' );

    buf = http_keepalive_send_recv( port:port, host:host, data:req );
    __ka_last_request[host + "#--#" + port] = req;
  }

  if( isnull( buf ) || buf == "" || ! buf )
    return FALSE;

  if( debug ) display( "\nContent:\n", buf, "\n" );

  if( check_header == TRUE ) {
    if( ! ereg( pattern:"^HTTP/[0-9]\.[0-9] 200.*", string:buf ) ) {
      return FALSE;
    }
  }

  if( extra_check ) {
    if( typeof( extra_check ) != "array" ) {
      extra_check = make_list( extra_check );
    }

    foreach _ec( extra_check ) {
      if( ! egrep( pattern:_ec, string:buf, icase:icase ) ) {
        return FALSE;
      }
    }
  }

  if( check_nomatch ) {
    if( typeof( check_nomatch ) != "array" ) {
      check_nomatch = make_list( check_nomatch );
    }

    foreach _nm( check_nomatch ) {
      if( egrep( pattern:_nm, string:buf, icase:icase ) ) {
        return FALSE;
      }
    }
  }

  if( egrep( pattern:pattern, string:buf, icase:icase ) )
    return buf;
  else
    return FALSE;
}

# @brief Creates a HTTP GET request for the specified URL, sends
#        the request to the target and receives the response.
#
# @param port     The HTTP port of the target.
# @param host     The (optional) HTTP hostname (e.g. from http_host_name with the dont_add_port:TRUE parameter
#                 or from get_host_name) of the remote target. Defaults to all known hostnames if not passed.
# @param url      The URL to request.
# @param bodyonly If TRUE only the body of the response is returned (not compatible with the nocache parameter set to FALSE).
# @param nocache  If TRUE the response is not saved into the knowledge base.
#
# @return The response to the HTTP GET request or NULL if no response was received.
#
function http_ka_recv_buf( port, host, url, bodyonly, nocache ) {

  local_var port, host, url, bodyonly, nocache;
  local_var res, req;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_ka_recv_buf" );
    return NULL;
  }

  if( ! url ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#http_ka_recv_buf" );
    return NULL;
  }

  if( ! host )
    host = http_host_name( dont_add_port:TRUE );

  if( ! nocache ) {
    if( ! egrep( pattern:"(\?|&|#|;|\[|\]|=)", string:url ) ) {
      if( bodyonly ) set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_ka_recv_buf(): nocache set to FALSE but bodyonly set to TRUE, response will contain the body." );
      res = http_get_cache( item:url, port:port, host:host );
      return res;
    }
  }

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, host:host, data:req, bodyonly:bodyonly );
  return res;
}

# @brief Re-opens an HTTP socket to the target system. If an existing socket existed / was
#        open before it will be closed. The newly created socket will be passed internally
#        to other functions like @http_keepalive_send_recv().
#
# @param port The HTTP port of the target.
# @param host The (mandatory) HTTP hostname (e.g. from http_host_name with the
#             dont_add_port:TRUE parameter or from get_host_name) of the remote target.
#
# @return NULL
#
function http_keepalive_reopen_connection( host, port ) {

  local_var host, port;
  # nb: __ka_sockets and __ka_port are global vars.

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_keepalive_reopen_connection" );
    return NULL;
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_keepalive_reopen_connection" );
    return NULL;
  }

  if( __ka_sockets[host + "#--#" + port] ) {
    http_close_socket( __ka_sockets[host + "#--#" + port] );
  }

  __ka_port = port;
  __ka_sockets[host + "#--#" + port] = http_open_socket( port );
}
