# SPDX-FileCopyrightText: 2008 Christian Eric Edjenguele
# SPDX-FileCopyrightText: Improved / extended code / detection routine since 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80004");
  script_version("2026-01-13T05:47:36+0000");
  script_tag(name:"last_modification", value:"2026-01-13 05:47:36 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Firebird / InterBase Database Server Service Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Christian Eric Edjenguele");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service6.nasl");
  script_require_ports("Services/unknown", 3050);

  script_tag(name:"summary", value:"TCP based detection of a Firebird / InterBase Database
  service.");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

function check_firebird_response( res ) {

  local_var res, status;

  if( isnull( res ) )
    return FALSE;

  # See https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-versions
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
  } else if( "Legacy_Auth" >< res || "Srp" >< res ) {
    status["installed"] = TRUE;
    if( "Srp256" >< res )
      status["proto_ver"] = 16;               # nb: SRP256 was introduced in Protocol version 16
    else
      status["proto_ver"] = 13;               # nb: SRP/Legacy Auth was introduced in Protocol version 13
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

firebird_auth_packet_v2 =
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

# https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html#wireprotocol-connect
v3_plugin_list = "Srp, Srp256, Legacy_Auth";

v3_userid = raw_string( 0x09,                     # CNCT_login
                        user_length,
                        user,
                        0x0a,                     # CNCT_plugin_list
                        strlen( v3_plugin_list ),
                        v3_plugin_list,
                        0x0b,                     # CNCT_client_crypt
                        0x04,                     # length
                        0x01, 0x00, 0x00, 0x00,
                        0x01,                     # CNCT_user
                        0x06,                     # user_length,
                        "vttest",                 # user,
                        0x04,                     # CNCT_host
                        host_length,
                        host,
                        0x06 );                   # CNCT_user_verification

if( strlen( v3_userid ) % 4 != 0 )
  v3_pad = crap( data:raw_string( 0x00 ), length:4 - ( strlen( v3_userid ) ) % 4 );

v3_userid = mkdword( strlen( v3_userid ) + 1 ) + v3_userid + v3_pad;

firebird_auth_packet_v3 =
  mkdword( 1 ) +              # Opcode: Connect (1)
  mkdword( 19 ) +             # Operation: Attach (19)
  mkdword( 3 ) +              # Version: 3
  mkdword( 36 ) +             # Client Architecture: Linux (36)
  mkdword( file_length ) + file + file_pad +
  mkdword( 1 ) +              # Version option count: 1
  v3_userid +
  # Preferred version
  raw_string( 0xff, 0xff, 0x80, 0x0f ) +   # Version
  mkdword( 1 ) +                           # Architecture: Generic (1)
  mkdword( 2 ) +                           # Minimum type: 0
  mkdword( 5 )  +                          # Maximum type: 5
  mkdword( 12 );                           # Preference weight: 4

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

send( socket:soc, data:firebird_auth_packet_v2 );
res = recv( socket:soc, length:1024 );
close( soc );

status = check_firebird_response( res:res );

if( isnull( status ) || status["proto_ver"] !~ "^[0-9]" ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    send( socket:soc, data:firebird_auth_packet_v3 );
    res = recv( socket:soc, length:1024 );
    close( soc );
  }
}

if( status = check_firebird_response( res:res ) ) {

  proto_ver = status["proto_ver"];

  set_kb_item( name:"firebird/db/detected", value:TRUE );
  set_kb_item( name:"firebird/sql/detected", value:TRUE );
  set_kb_item( name:"firebird/sql/gds_db/detected", value:TRUE );
  set_kb_item( name:"firebird/sql/gds_db/port", value:port );

  service_register( port:port, proto:"gds_db" );

  report = "A Firebird / Interbase Database service is running at this port.";

  if( proto_ver != "unknown" ) {
    report += '\n\nSupported protocol version: ' + proto_ver;
    set_kb_item( name:"firebird/sql/gds_db/" + port + "/proto_ver", value:proto_ver );
  }

  log_message( port:port, data:report );

  exit( 0 );
}

exit( 0 );
