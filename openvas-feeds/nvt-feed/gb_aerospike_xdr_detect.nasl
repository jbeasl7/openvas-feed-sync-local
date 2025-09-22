# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140130");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-01-27 13:21:27 +0100 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Aerospike Database Detection (XDR)");

  script_tag(name:"summary", value:"Cross-Datacenter Replication (XDR) based detection of the
  Aerospike Database.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3000);

  script_xref(name:"URL", value:"https://aerospike.com/docs/server/architecture/xdr");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:3000 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

cmd = 'version\n';

req = raw_string( 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, strlen( cmd ) ) + cmd;

send( socket:soc, data:req );
recv = recv( socket:soc, length:8 );

if( strlen( recv ) != 8 || hexstr( recv ) !~ "^02010000000000" ) {
  close( soc );
  exit( 0 );
}

len = ord( recv[7] );

if( len < 5 || len > 1024 ) {
  close( soc );
  exit( 0 );
}

recv = recv( socket:soc, length:len );
close( soc );

if( strlen( recv ) != len || "Aerospike" >!< recv )
  exit( 0 );

recv = chomp( recv );

set_kb_item( name:"aerospike/detected", value:TRUE );
set_kb_item( name:"aerospike/xdr/port", value:port );
set_kb_item( name:"aerospike/xdr/" + port + "/concluded", value:recv );

version = "unknown";
edition = "Unknown Edition";

# Aerospike Community Edition build 3.11.0.2
# Aerospike Community Edition build 4.9.0.5
v = eregmatch( pattern:"build ([0-9.-]+)", string:recv );
if( ! isnull( v[1] ) )
  version = v[1];

if( "Community Edition" >< recv )
  edition = "Community Edition";
else if( "Enterprise Edition" >< recv )
  edition = "Enterprise Edition";

service_register( port:3000, proto:"aerospike_xdr" );

log_message( port:port, data:"An XDR based Aerospike Database service is running on this port." );

set_kb_item( name:"aerospike/edition", value:edition );
set_kb_item( name:"aerospike/xdr/" + port + "/version", value:version );

exit( 0 );
