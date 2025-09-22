# SPDX-FileCopyrightText: 2005 Nicolas Gregoire
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10144");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Microsoft SQL (MSSQL) Server Detection (TCP/IP Listener)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Nicolas Gregoire");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 1433);

  script_tag(name:"summary", value:"Microsoft SQL (MSSQL) Server detection based on an exposed
  TCP/IP listener.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("os_func.inc");
include("mssql.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:1433 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

payload = raw_string( 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
                      0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
                      0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
                      0x01, 0xff, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

len = strlen( payload );

# TDS7 pre-login message (http://msdn.microsoft.com/en-us/library/dd357559.aspx)
req = raw_string( 0x12, 0x01 ) +
      mkword( len + 8 ) +
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +
      payload;

send( socket:soc, data:req );
buf = recv( socket:soc, length:4096 );
close( soc );

if( ! buf )
  exit( 0 );

len = strlen( buf );
if( len < 18 )
  exit( 0 );

res_type = ord( buf[0] );
if( res_type != 4 )
  exit( 0 );

pos = 8;

if( ord( buf[ pos ] ) != 0 )
  exit( 0 );

off  = getword( blob:buf, pos:pos + 1 );
blen = getword( blob:buf, pos:pos + 3 );
pos += off;

if( blen < 6 || ( pos + 6 ) > strlen( buf ) )
  exit( 0 );

version = ord( buf[ pos ] ) + "." + ord( buf[ pos + 1 ] ) + "." + getword( blob:buf, pos:pos + 2 ) + "." + getword( blob:buf, pos:pos + 4 );
service_register( port:port, proto:"mssql" );
concluded  = '\n  TDS7 prelogin message response version option: ' + version;

os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port, desc:"Microsoft SQL (MSSQL) Server Detection (TCP/IP Listener)", runs_key:"windows" );

set_kb_item( name:"OpenDatabase/found", value:TRUE );

set_kb_item( name:"microsoft/sqlserver/detected", value:TRUE );
set_kb_item( name:"microsoft/sqlserver/" + port + "/detected", value:TRUE );
set_kb_item( name:"microsoft/sqlserver/tcp_listener/detected", value:TRUE );
set_kb_item( name:"microsoft/sqlserver/tcp_listener/" + port + "/detected", value:TRUE );

set_kb_item( name:"microsoft/sqlserver/tcp_listener/" + port + "/installs",
             value:port + "#---#unknown#---#" + port + "/tcp" + "#---#" + version + "#---#" + concluded );

# nb: We should always / generally do a log_message() for service detections even if there is a
# consolidation.
log_message( port:port, data:"A Microsoft SQL (MSSQL) Server TCP/IP listener seems to be running on this port. Concluded from:" + concluded );

exit( 0 );
