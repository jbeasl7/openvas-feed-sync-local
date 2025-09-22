# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108082");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-02-10 13:00:00 +0100 (Fri, 10 Feb 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache JServ Protocol (AJP) v1.3 Detection (TCP)");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 8009);

  script_xref(name:"URL", value:"https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html");

  script_tag(name:"summary", value:"TCP based detection of services supporting the Apache JServ
  Protocol (AJP) in version 1.3.");

  script_tag(name:"insight", value:"The AJP protocol is used in various products like e.g. Apache
  Tomcat, JBoss or Wildfly.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:8009 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

# CPing Request
# https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
req = raw_string( 0x12, 0x34, 0x00, 0x01, 0x0a );
send( socket:soc, data:req );
buf = recv( socket:soc, length:10 ); # nb: CPong Reply has a length of 5 but using 10 here to avoid possible false positives with the exact match down below.
close( soc );

if( ! buf || strlen( buf ) != 5 )
  exit( 0 );

# The CPong Reply
if( hexstr( buf ) =~ "^4142000109$" ) {

  # nb:
  # - Store link between this and e.g. gb_apache_tomcat_ajp_wan_access.nasl
  # - We don't use the host_details.inc functions in both so we need to call this directly
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  set_kb_item( name:"apache/ajp/detected", value:TRUE );
  set_kb_item( name:"apache/ajp/" + port + "/detected", value:TRUE );
  service_register( port:port, proto:"ajp13" );
  log_message( port:port, data:"A service supporting the Apache JServ Protocol (AJP) v1.3 seems to be running on this port." );
}

exit( 0 );
