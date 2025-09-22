# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11149");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP login page");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "logins.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  # We first visit this page to get a cookie, just in case
  script_add_preference(name:"Login page :", type:"entry", value:"/", id:1);
  # Then we submit the username & password to the right form
  script_add_preference(name:"Login form :", type:"entry", value:"", id:2);
  # Here, we allow some kind of variable substitution.
  script_add_preference(name:"Login form fields :", type:"entry", value:"user=%USER%&pass=%PASS%", id:3);

  script_tag(name:"summary", value:"This script logs onto a web server through a login page and
  stores the authentication / session cookie.");

  script_tag(name:"insight", value:"- The used login needs to be configured separately in / via the
  'HTTP account' and 'HTTP password' preferences of the VT 'Login configurations' (OID:
  1.3.6.1.4.1.25623.1.0.10870)

  - This configured login will be used in the '%USER%' and '%PASS%' placeholders configured within
  the 'Login form fields' preference of this VT

  - The 'Login page' and 'Login form' preferences of this VT needs to be configured before a login
  is tried");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

http_login_form   = script_get_preference( "Login form :", id:2 );
http_login_fields = script_get_preference( "Login form fields :", id:3 );
if( ! http_login_form || ! http_login_fields ) exit( 0 );

http_login_page = script_get_preference( "Login page :", id:1 );

http_login = get_kb_item( "http/login" );
if( http_login ) {
  http_login_fields = ereg_replace( string:http_login_fields, pattern:"%USER%", replace:http_login );
}

http_pass = get_kb_item( "http/password" );
if( http_pass ) {
  http_login_fields = ereg_replace( string:http_login_fields, pattern:"%PASS%", replace:http_pass );
}

cookie1 = "";
referer = "";

port = http_get_port( default:80 );

if( http_login_page ) {

  # nb: Should be always before the first http_open_socket() call.
  req = http_get( port:port, item:http_login_page );

  if( ! soc = http_open_socket( port ) )
    exit( 0 );

  send( socket:soc, data:req );
  r = http_recv_headers2( socket:soc );
  #r2 = recv( socket:soc, length:1024 );
  http_close_socket( soc );

  cookies = egrep( pattern:"Set-Cookie2?\s*:", string:r );
  if( cookies) {
    cookie1 = ereg_replace( string:cookies, pattern:"^Set-Cookie", replace:"Cookie" );
    c = ereg_replace( string:cookie1, pattern:"^Cookie2?\s*:\s*", replace:"" );
  }

  trp = get_port_transport( port );
  if( trp > ENCAPS_IP )
    referer = "Referer: https://";
  else
    referer = "Referer: http://";
  referer = string( referer, get_host_name() );
  if( ( ( trp == 1 ) && ( port != 80 ) ) || ( ( trp > 1 ) && ( port != 443 ) ) )
    referer = string(referer, ":", port);
  if( ereg( pattern: "^[^/]", string:http_login_page ) )
    referer = string( referer, "/" );
  referer = string( referer, http_login_page, "\r\n" );
}

# nb: Note the same for http_post as for http_get() above.
req = http_post( port:port, item:http_login_form, data:http_login_fields );
req = ereg_replace( string:req, pattern:"Content-Length\s*:\s*", replace:string( "Content-Type: application/x-www-form-urlencoded\r\n", referer, cookie1, "Content-Length: " ) );

soc = http_open_socket( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:req );
r = http_recv_headers2( socket:soc );
http_close_socket( soc );

h = split( r );

foreach r( h ) {

  # Failed - permission denied or bad gateway or whatever
  if( egrep( pattern:"HTTP/[019.]+ +[45][0-9][0-9]", string:r ) ) exit( 0 );

  if( r =~ "^Set-Cookie" ) {
    if( ! first_cookie ) {
      cookies_string += ereg_replace( string:r, pattern:"^Set-Cookie", replace:"Cookie" );
      cookies_string  = chomp( cookies_string );
      first_cookie    = TRUE;
    } else {
      cookies_string += ereg_replace( string:r, pattern:"^Set-Cookie\s*:", replace:";" );
      cookies_string  = chomp( cookies_string );
    }

    # TBD: Why is this commented out? set_kb_item( name:string( "/tmp/http/auth/", port ), value:cookies );
    # TBD: Why is this commented out? set_kb_item( name:"http/auth", value:cookies );
    c = ereg_replace( string:cookies, pattern:"^Cookie2?\s*:\s*", replace:"" );
  } else if( cookie1 ) {
    set_kb_item( name:string( "/tmp/http/auth/", port ), value:cookie1 );
  }
}

if( cookies_string ) {
  set_kb_item( name:string( "/tmp/http/auth/", port ), value:cookies_string );
}

exit( 0 );
