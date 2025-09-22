# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105065");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-07-18 18:29:45 +0200 (Fri, 18 Jul 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Cassandra Detection (Thrift)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  # None of the current find_service* is detecting this service so run it early by adding a dep to
  # find_service.nasl
  script_dependencies("find_service.nasl",
                      "nessus_detect.nasl"); # See below...
  script_require_ports("Services/unknown", 9160);

  script_tag(name:"summary", value:"Thrift based detection of Apache Cassandra.");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:9160 ); # rpc_port can be changed

# nb: Set by nessus_detect.nasl if we have hit a service described in the notes below
# No need to continue here as well...
if( get_kb_item( "generic_echo_test/" + port + "/failed" ) )
  exit( 0 );

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test
# multiple times...
if( ! get_kb_item( "generic_echo_test/" + port + "/tested" ) ) {
  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );
  send( socket:soc, data:string( "TestThis\r\n" ) );
  r = recv_line( socket:soc, length:10 );
  close( soc );
  # We don't want to be fooled by echo & the likes
  if( "TestThis" >< r ) {
    set_kb_item( name:"generic_echo_test/" + port + "/failed", value:TRUE );
    exit( 0 );
  }
}

set_kb_item( name:"generic_echo_test/" + port + "/tested", value:TRUE );

if( ! soc = open_sock_tcp( port ) )
  exit(0);

cmd = "execute_cql3_query";
cmd_len = strlen( cmd ) % 256 ;

sql = "select release_version from system.local;";
sql_len = strlen( sql ) % 256 ;

req = raw_string( 0x80,                                       # Protocol id: Strict Binary Protocol
                  0x01,                                       # Version
                  0x00,
                  0x01,                                       # Message type: CALL
                  0x00, 0x00, 0x00, cmd_len ) +
      cmd +                                                   # Method
      raw_string( 0x00, 0x00, 0x00, 0x00,                     # Sequence id
                  0x0b,                                       # Type: T_BINARY
                  0x00, 0x01,                                 # Field id
                  0x00, 0x00, 0x00, sql_len ) +
      sql +
      raw_string( 0x08,                                       # Type: T_I32
                  0x00, 0x02,                                 # Field id
                  0x00, 0x00, 0x00, 0x02,                     # Integer32
                  0x08,                                       # Type: T_I32
                  0x00, 0x03,                                 # Field id
                  0x00, 0x00, 0x00, 0x01,                     # Integer32
                  0x00 );                                     # Type: T_STOP


alen = strlen( req ) % 256;
req = raw_string( 0x00, 0x00, 0x00, alen ) + req;

send( socket:soc, data:req );
recv = recv( socket:soc, length:4096 );
close( soc );

if( ! recv || "execute_cql3_query" >!< recv )
  exit( 0 );

# Apache Cassandra detected
# Note that e.g. Shodan is showing a Version: 19.39.0 but that seems wrong in that case as this
# is the API-Version.
version = "unknown";

set_kb_item( name:"apache/cassandra/detected", value:TRUE );
set_kb_item( name:"apache/cassandra/thrift/detected", value:TRUE );
set_kb_item( name:"apache/cassandra/thrift/port", value:port );

ret = bin2string( ddata:recv, noprint_replacement:" " );
set_kb_item( name:"apache/cassandra/thrift/" + port + "/concluded", value:ret );

vers = eregmatch( pattern:"release_version\s*([0-9.]+)", string:ret );
if( ! isnull( vers[1] ) )
  version = vers[1];

set_kb_item( name:"apache/cassandra/thrift/" + port + "/version", value:chomp( version ) );

service_register( port:port, proto:"cassandra" );

log_message( port:port, data:"An Apache Thrift based service of Apache Cassandra is running on this port." );

exit( 0 );
