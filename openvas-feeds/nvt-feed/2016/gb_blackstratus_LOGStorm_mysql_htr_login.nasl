# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140093");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-05 17:47:01 +0100 (Mon, 05 Dec 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("Blackstratus LOGStorm Default Credentials (MySQL Protocol)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("mysql_mariadb/remote/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote MySQL service has the password 'htr_pwd' for the
  user 'htr'.");

  script_tag(name:"vuldetect", value:"Tries to login via the MySQL protocol using known default
  credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("byte_func.inc");
include("host_details.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cpe_list = make_list( "cpe:/a:oracle:mysql", "cpe:/a:mariadb:mariadb" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

if( get_kb_item( "MySQL/" + port + "/blocked" ) )
  exit( 0 );

if( ! sock = open_sock_tcp( port ) )
  exit( 0 );

res = recv( socket:sock, length:4 );
if( ! res || strlen( res ) != 4 ) {
  close( sock );
  exit( 0 );
}

username = "htr";
password = "htr_pwd";

# TBD: Put this / parts of it into a function? Some code is shared with e.g.:
# - 2012/gb_mysql_mariadb_default_creds.nasl
# - 2012/gb_scrutinizer_54731.nasl

# - https://web.archive.org/web/20210614014328/https://dev.mysql.com/doc/internals/en/client-server-protocol.html
# - https://web.archive.org/web/20210506172939/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV9
# - https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
# - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v9.html
# - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
#
# nb:
# - Packet Length seems to be 4 (checked above) for protocol version 9 and below
# - With protocol version 10 it might be longer
plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );
res = recv( socket:sock, length:plen );

if( "mysql_native_password" >< res )
  native = TRUE;

for( i = 0; i < strlen( res ); i++ ) {
  if( ord( res[i] ) != 0 )
    ver += res[i];
  else
    break;
}

p = strlen( ver );
if( p < 5 ) {
  close( sock );
  exit( 0 );
}

caps = substr( res, 14 + p, 15 + p );
if( ! caps ) {
  close( sock );
  exit( 0 );
}

caps = ord( caps[0] ) | ord( caps[1] ) << 8;
proto_is_41 = ( caps & 512 );

if( ! proto_is_41 ) {
  close( sock );
  exit( 0 );
}

salt = substr( res, 5 + p, 12 + p );

if( strlen( res ) > ( 44 + p ) )
  salt += substr( res, 32 + p, 43 + p );

sha_pass1 = SHA1( password );
sha_pass2 = SHA1( sha_pass1 );
sha_pass3 = SHA1( salt + sha_pass2 );

l = strlen( sha_pass3 );

for( i = 0; i < l; i++ )
  pass += raw_string( ord( sha_pass1[i] ) ^ ord( sha_pass3[i] ) );

req = raw_string( 0x05, 0xa6, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00 );

req += raw_string( username, 0x00 );
req += raw_string( 0x14, pass );

if( native )
  req += raw_string( 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00 );

len = strlen( req );
req = raw_string( len & 0xff, ( len >> 8 ) & 0xff, ( len >> 16 ) & 0xff, 0x01 ) + req;

send( socket:sock, data:req );
res = recv( socket:sock, length:4 );

if( ! res || strlen( res ) < 4 ) {
  close( sock );
  exit( 0 );
}

plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );

res = recv( socket:sock, length:plen );
if( ! res || strlen( res ) < plen ) {
  close( sock );
  exit( 0 );
}

errno = ord( res[2] ) << 8 | ord( res[1] );

if( errno > 0 || errno == "" ) {
  close( sock );
  exit( 0 );
}

cmd = "show databases";
len = strlen( cmd ) + 1;
req = raw_string( len & 0xff, ( len >> 8 ) & 0xff, ( len >> 16 ) & 0xff, 0x00, 0x03, cmd );

send( socket:sock, data:req );

z = 0;
while( TRUE ) {
  z++;
  if( z > 15 ) {
    close( sock );
    exit( 0 );
  }

  res = recv( socket:sock, length:4 );

  if( ! res || strlen( res ) < 4 ) {
    close( sock );
    exit( 0 );
  }

  plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );

  res = recv( socket:sock, length:plen );
  if( ! res || strlen( res ) < plen )
    break;

  if( "information_schema" >< res ) {
    close( sock );

    data = 'It was possible to login as user "' + username + '"';
    data += ' with password "' + password + '".';

    security_message( port:port, data:data );
    exit( 0 );
  }
}

close( sock );
exit( 0 );
