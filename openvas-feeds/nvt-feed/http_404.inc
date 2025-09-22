# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Global var to avoid that we're repeatedly asking redis for something we already know.
global_var _http_no404_string_array;

# nb: key is the host+port or NULL (if not previously checked), value a string or FALSE
_http_no404_string_array = make_array();

# @brief Returns a list of strings which are known to be thrown by a web server / web application
#        to indicate if a specific file / URL is not found.
#
# @note The strings are including escaped chars (e.g. "\." instead of ".") thus the caller needs to
#       either use egrep() or any other regex relevant function like eregmatch().
#
# @return A list of strings as described in the function description.
#
function http_get_no404_pattern() {

  local_var errmessages_404;

  # nb:
  # - DDI_Directory_Scanner.nasl and no404.nasl are using an egrep() so we can use regex pattern
  #   here
  # - This also means that special regex chars like e.g. [, . or the like needs to be escaped
  # - TBD: Previously the following was included DDI_Directory_Scanner.nasl but not added yet / for
  #   now as it might be too generic:
  #   errmsg[ei++] = "unknown";

  errmessages_404 = make_list(

    # TBD: Next two might be too generic?
    "not found",
    "404",

    "error has occurred",
    "FireWall-1 message",
    "Reload acp_userinfo database",
    "IMail Server Web Messaging",
    "HP Web JetAdmin",
    "Error processing SSI file",
    "ExtendNet DX Configuration",
    "Unable to complete your request due to added security features",
    "Client Authentication Remote Service</font>",
    "Bad Request",

    # Webmin
    "<form action=/session_login\.cgi",
    "Webmin server",

    "Management Console",

    # As in "<input type=password>"
    "TYPE=password",

    # Tivoli server administrator
    # nb: Initially two variants of this string was included in this file, one with and one without
    # a full stop. As the string is already quite strict the one without the full stop has been
    # included here.
    "The userid or password that was specified is not valid",

    "Access Failed",
    "Please identify yourself:",
    "forcelogon\.htm",
    "encountered an error while publishing this resource",
    "No web site is configured at this address",
    "No website is configured at this address",
    'name=qt id="search" size=40 value=" "',
    "PHP Fatal error:  Unable to open",
    "RSA SecurID User Name Request",
    "Error Occurred While Processing Request",
    "Web access denied",
    "Error Page",
    "The page you requested doesn't exist",
    "TYPE='password'",
    'TYPE="password"',
    "This version of Compaq's management software has added",
    "Error - Bad Request",
    "Insufficient Access",

    # Drupal
    "The requested page could not be found\.",

    "Content-Length: 0",
    "submitLogin\(\)",
    ">Login<",

    # Java applications
    "<u>The requested resource is not available\.</u>",

    # Unknown, originally included in gb_hikvision_ip_camera_http_detect.nasl
    "Document Error: Not Found",

    # Pi-hole catchall page
    "Pi-<(b|strong)>hole</(b|strong)>: Your black hole for Internet advertisements",

    # Pi-hole error page
    "\[ERROR\]: Unable to parse results from <i>queryads\.php</i>",

    # IIS and probably more
    "cannot be found",

    # Symfony framework, should throw an 404 Not Found but there might be other deployments where this doesn't apply.
    "No route found for ",

    # Discourse, should throw an 404 Not Found but there might be other deployments where this doesn't apply.
    # nb: the "." between "doesn" and "t" is expected as we can't use UTF-8 chars in VTs yet...
    "Oops! That page doesn.t exist or is private\.",

    # Both seen on SolarView Compact systems with a 200 status code:
    "<TITLE>Error 404</TITLE>",
    "<B>Error 404 : File Not Found\.</B>",

    # On:
    # Server: pve-api-daemon/3.0
    # the following has been seen on non-existing pages:
    # HTTP/1.1 501 no such file '/resin-doc/'
    "no such file",

    # SAP NetWeaver
    "Requested resource does not exist",

    # Seen on Adobe Experience Manager (AEM)
    "The requested URL was rejected\.",

    # VMware Operations for Logs which had thrown a 403 error including this message for non-existing pages
    "Sorry, the page you were looking for does not exist",

    # AkamaiGHost might throw a 400 instead of 404 on non-existing files, see e.g. https://seclists.org/pen-test/2003/Oct/2
    "<TITLE>Invalid URL</TITLE>"
  );

  return errmessages_404;
}

# @brief Returns a string which was identified by no404.nasl for a remote web server
#        returning a 200 HTTP (Found) status code for non-existing pages. The string
#        contains a pattern like e.g. "not found" which can be used by a VT as a sign
#        that the web server hasn't returned the expected result about the existence
#        of a file/url. It will also save the information in an internal array to avoid
#        that redis is queried again for the same info.
#
# @param port The port of the remote server.
# @param host The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#             parameter or get_host_name) of the remote server. If no host parameter
#             is passed http_host_name will be called automatically and a debug
#             message is logged into the KB. A special "*" string can be passed
#             where the function will return the string of the first hostname.
#
# @return An identified string if the remote web server is returning a 200 status code
#         to non-existing pages, FALSE otherwise and NULL in the case where the port
#         parameter wasn't passed.
#
# @todo Maybe implement an additional "subdir" check as some pages might return different
#       strings based on different subdirs. This would require an update to no404.nasl as well.
#
function http_get_no404_string( port, host ) {

  local_var port, host;
  local_var no404_string, no404_string_list, _no404_string;
  # nb: _http_no404_string_array is a global_var (see on top)

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_get_no404_string" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_get_no404_string" );
    host = http_host_name( dont_add_port:TRUE );
  }

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( _http_no404_string_array[host+port] ) ) {
    if( no404_string = _http_no404_string_array[host+port] )
      return no404_string;
    else
      return FALSE;
  }

  if( host == "*" ) {
    no404_string_list = get_kb_list( "www/*/" + port + "/no404_string" );
    if( ! no404_string_list || typeof( no404_string_list ) != "array" ) {
      no404_string = FALSE;
    } else {
      foreach _no404_string( no404_string_list ) {
        if( _no404_string && strlen( _no404_string ) > 0 ) {
          no404_string = _no404_string;
          break;
        }
      }
    }
  } else {
    no404_string = get_kb_item( "www/" + host + "/" + port + "/no404_string" );
  }

  if( no404_string && strlen( no404_string ) > 0 )
    _http_no404_string_array[host+port] = no404_string;
  else
    _http_no404_string_array[host+port] = FALSE;

  return no404_string;
}

# @brief Sets a specific string which should be assumed by VTs as a sign for a
#        "file not found" if a remote web server isn't responding with a 200 HTTP
#        status code to non-existent files. The string is set within the following
#        KB entry: "www/" + host "/" + port + "/no404_string"
#
# @param port   The port of the remote server.
# @param host   The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#               parameter or get_host_name) of the remote server.
# @param string The string to set within the mentioned KB entry.
#
# @return TRUE if the string was successfully saved within the KB and
#         NULL if no port, host or string parameter was passed.
#
# @todo See the todo for @ref http_get_no404_string above.
#
function http_set_no404_string( port, host, string ) {

  local_var port, host, string;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_set_no404_string" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_set_no404_string" );
    return NULL;
  }

  if( ! string ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#string#-#http_set_no404_string" );
    return NULL;
  }

  set_kb_item( name:"www/" + host + "/" + port + "/no404_string", value:string );
  return TRUE;
}

# @brief Checks if a specific passed data contains a 40x HTTP status code.
#        If no such status code was identified the KB is checked additionally
#        (by using @ref http_get_no404_string) if the remote web server is
#        responding with a 200 HTTP status code to a non-existent file/url.
#
# @param port The port of the remote server.
# @param host The hostname (e.g. from http_host_name with the dont_add_port:TRUE
#             parameter or get_host_name) of the remote server.
# @param data The data which is checked in form of a HTTP response.
#
# @return TRUE if the passed data contains a 40x HTTP status code or a string
#         as described in @ref http_get_no404_string was identified by no404.nasl,
#         FALSE otherwise and NULL if no port, host or data parameter was passed
#         or the data parameter doesn't contain a valid HTTP response.
#
# @todo See the todo for @ref http_get_no404_string above.
#
function http_data_has_40x( port, host, data ) {

  local_var port, host, data;
  local_var no404;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#http_data_has_40x" );
    return NULL;
  }

  if( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#http_data_has_40x" );
    return NULL;
  }

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#http_data_has_40x" );
    return NULL;
  }

  if( ! ereg( string:data, pattern:"^HTTP/1\.[01] +[0-9]+" ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_data_has_40x(): No data containing a valid HTTP status code passed in data variable." );
    return NULL;
  }

  if( ereg( string:data, pattern:"^HTTP/1\.[01] +40[0-9]" ) )
    return TRUE;

  no404 = http_get_no404_string( port:port, host:host );
  if( no404 && no404 >< data )
    return TRUE;
  else
    return FALSE;
}
