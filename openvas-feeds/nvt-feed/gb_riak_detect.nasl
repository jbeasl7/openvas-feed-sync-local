# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105589");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-30 12:30:23 +0200 (Wed, 30 Mar 2016)");
  script_name("Basho Riak Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 8087);
  exit(0);
}


include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:8087 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# http://docs.basho.com/riak/latest/dev/references/protocol-buffers/
req = raw_string( 0x00, 0x00, 0x00, 0x01, 0x01 ); # RpbPingReq
send( socket:soc, data:req );
recv = recv( socket:soc, length:5 );

if( strlen( recv ) != 5 || ord( recv[4] ) != 2 ) # 2 = Message Code RpbPingResp
{
  close( soc );
  exit( 0 );
}

req = raw_string( 0x00, 0x00, 0x00, 0x01, 0x07 ); # RpbGetServerInfoReq
send( socket:soc, data:req );
recv = recv( socket:soc, length:4, min:4  );

if( strlen( recv ) < 4 ) exit( 0 );

len = ( ord( recv[0] ) << 24 | ord( recv[1] ) << 16 | ord( recv[2] ) << 8 | ord( recv[3] ) );

if( len < 1 || len > 65535 ) exit( 0 );

recv = recv( socket:soc, length:len, min:len );

close( soc );

# 8 = Message Code RpbGetServerInfoResp
if( ord( recv[0] ) != 8 || "riak@" >!< recv ) exit( 0 );

hn_len = ( ord( recv[2] ) + 2 );
node = substr( recv, 3, hn_len );

vlen = ord( substr( recv, ( hn_len + 2 ), ( hn_len + 2 ) ) );
version = substr( recv, ( hn_len + 3), ( hn_len + 3 + vlen ) );

cpe = "cpe:/a:basho:riak";

if( version )
  cpe += ':' + version;
else
  version = 'unknown';

service_register( port:port, proto:"riad_pb" );

set_kb_item( name:"riad/installed", value:TRUE );
set_kb_item( name:"riad/pb/port", value:port );

register_product( cpe:cpe, location:port + "/tcp", port:port, service:'riad_pb' );

report = build_detection_report( app:"Basho Riak", version:version, install: port + '/tcp',cpe:cpe, extra:'\nNode: ' + node + '\n' );

log_message( port:port, data:report );
exit( 0 );

