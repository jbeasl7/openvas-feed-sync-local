# SPDX-FileCopyrightText: 2008 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80004");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Firebird / InterBase Database Server Service Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Christian Eric Edjenguele");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service6.nasl");
  script_require_ports("Services/unknown", 3050);

  script_tag(name:"summary", value:"A Firebird / InterBase Database Service is running at this
  host.");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

function check_firebird_response( res ) {

  local_var res, status;

  if( isnull( res ) ) {
    return FALSE;
  }

  # Protocol version 10 supported
  if( "030000000a0000000100000003" >< hexstr( res ) ) {
    status["installed"] = TRUE;
    status["proto_ver"] = 10;
    return status;
  # Protocol version 8 supported
  } else if( "03000000080000000100000003" >< hexstr( res ) ) {
    status["installed"] = TRUE;
    status["proto_ver"] = 8;
    return status;
  } else if( hexstr( res ) == "00000004" ) {  # Opcode: Rejected
    status["installed"] = TRUE;
    status["proto_ver"] = "unknown";
    return status;
  } else {
    # Not installed or unknown protocol version
    return FALSE;
  }
}

port = unknownservice_get_port( default:3050 );

vt_strings = get_vt_strings();

# forge the firebird negotiation protocol for 2.5
# from a wireshark dump of a connection with a firebird client
# See also https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-gdsdb.c
file        = "/" + vt_strings["lowercase"] + ".fdb";
file_length = strlen( file );
if( file_length % 4 != 0 )
  file_pad = crap( data:raw_string( 0x00 ), length:4 - ( file_length % 4 ) );

user        = vt_strings["lowercase"];
user_length = strlen( user );
host        = this_host_name();
host_length = strlen( host );
u_h_length  = user_length + host_length;

if( ( u_h_length + 2 ) % 4 != 0 )
  u_h_pad = crap( data:raw_string( 0x00 ), length:4 - ( ( u_h_length + 2 ) % 4 ) );

firebird_auth_packet =
  mkdword( 1 ) +              # Opcode: Connect (1)
  mkdword( 19 ) +             # Operation: Attach (19)
  mkdword( 2 ) +              # Version: 2
  mkdword( 36 ) +             # Client Architecture: Linux (36)
  mkdword( file_length ) + file + file_pad +
  mkdword( 2 ) +              # Version option count: 2 -> See below
  mkdword( u_h_length + 6 ) +
  raw_string( 0x01 ) +        # Currently unknown
  raw_string( user_length ) + user +
  raw_string( 0x04 ) +        # Currently unknown
  raw_string( host_length ) + host +
  raw_string( 0x06, 0x00 ) +  # Currently unknown
  u_h_pad +
  # Preferred version 1
  mkdword( 8 ) +              # Version: 8
  mkdword( 1 ) +              # Architecture: Generic (1)
  mkdword( 2 ) +              # Minimum type: 2
  mkdword( 3 ) +              # Maximum type: 3
  mkdword( 2 ) +              # Preference weight: 2
  # Preferred version 2
  mkdword( 10 ) +             # Version: 10
  mkdword( 1 )  +             # Architecture: Generic (1)
  mkdword( 2 )  +             # Minimum type: 2
  mkdword( 3 )  +             # Maximum type: 3
  mkdword( 4 );               # Preference weight: 4

# TODO: 3.0
# https://www.firebirdsql.org/file/documentation/release_notes/html/en/3_0/rnfb30-security-new-authentication.html

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

send( socket:soc, data:firebird_auth_packet );
res = recv( socket:soc, length:1024 );
close( soc );

if( status = check_firebird_response( res:res ) ) {
  installed = status["installed"];
  proto_ver = status["proto_ver"];

  set_kb_item( name:"firebird/db/detected", value:TRUE );
  service_register( port:port, proto:"gds_db" );

  report = "A Firebird / Interbase Database service is running at this port.";

  if( proto_ver != "unknown" )
    report += '\n\nSupported protocol version: ' + proto_ver;

  log_message( port:port, data:report );

  exit( 0 );
}

exit( 0 );
