# SPDX-FileCopyrightText: 2006 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19288");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VNC Supported 'security types' Detection (TCP)");
  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Michel Arboi");
  script_family("Service detection");
  script_dependencies("vnc.nasl");
  script_require_ports("Services/vnc", 5900);
  script_mandatory_keys("vnc/detected");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc6143");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc7869");

  script_tag(name:"summary", value:"TCP based detection of the available remote Virtual Network
  Computing (VNC) 'security types'.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("global_settings.inc");
include("network_func.inc");

global_var s;
function on_exit() { if (s) close(s); }

port = service_get_port( default:5900, proto:"vnc" );

if( ! s = open_sock_tcp( port ) )
  exit( 0 );

r = recv( socket:s, length:512, min:12 );
if( strlen( r ) < 12 ) exit( 0 );

v = eregmatch( string:r, pattern:'^RFB ([0-9]+)\\.([0-9]+)\n' );
if( isnull( v ) ) exit( 0 );

major = int( v[1] );
minor = int( v[2] );

debug_print( 'RFB protocol version = ', major, '.', minor, '\n' );

if( major < 3 ) {
  debug_print( 'Unsupported RFB major protocol version ', major, '.', minor, '\n' );
  exit( 0 );
}

# Send back the same protocol
send( socket:s, data:r );

# Security types names
rfb_sec = make_array( 0, "Invalid",
                      1, "None",
                      2, "VNC authentication",
                      5, "RA2",
                      6, "RA2ne",
                      16, "Tight",
                      17, "Ultra",
                      18, "TLS" );

if( major == 3 && minor >= 3 && minor < 7 ) {

  r = recv( socket:s, min:4, length:4 );
  if( strlen( r ) != 4 ) {
    debug_print( 'Could not read security type\n' );
    exit( 0 );
  }

  st = ntohl( n:r );
  report = strcat( 'The remote VNC server chose security type #', st );
  if( rfb_sec[ st ] ) report = strcat( report, ' (', rfb_sec[st], ')' );
  log_message( port:port, data:report );
  set_kb_item( name:"vnc/" + port + "/security_types", value:st );
  set_kb_item( name:"vnc/security_types/detected", value:TRUE );

} else if( major > 3 || minor >= 7 ) {

  r = recv( socket:s, min:1, length:1 );
  if( strlen( r ) < 1 ) {
    debug_print( 'Could not read number of security types\n' );
    exit( 0 );
  }

  n = ord( r );
  if( n == 0 ) { # rejected connection
    reason = '';
    r = recv( socket:s, min:4, length:4 );
    if( strlen( r ) == 4 ) {
      l = htonl( n:r );
      reason = recv( socket:s, length:l );
    }

    report = 'The remote VNC server rejected the connection.\n';
    if( strlen( reason ) > 0 ) {
      log_message( port:port, data:strcat( report, 'Reason: ', reason ) );
    } else {
      log_message( port:port, data:strcat( report, 'The scanner could not read the reason why.' ) );
    }
  } else {
    report = 'The remote VNC server supports those security types:\n';
    min = 9999;
    for( i = 0; i < n; i++ ) {
      r = recv( socket:s, min:1, length:1 );
      if( strlen( r ) < 1 ) {
       debug_print( 'Could not read security type #', i, '/', n );
       break;
      }
      st = ord( r );
      set_kb_item( name:"vnc/" + port + "/security_types", value:st );
      set_kb_item( name:"vnc/security_types/detected", value:TRUE );
      if( rfb_sec[st] ) {
        report = strcat( report, '\n', st, ' (', rfb_sec[st], ')' );
      } else {
        report = strcat( report, '\n', st );
      }
      if( st < min ) min = st;
    }
    log_message( port:port, data:report );
  }
} else {
  debug_print( 'Unsupported RFB minor protocol version ', major, '.', minor, '\n' );
  exit( 0 );
}

if( service_is_unknown( port:port ) ) service_register( port:port, proto:'vnc' );

exit( 0 );
