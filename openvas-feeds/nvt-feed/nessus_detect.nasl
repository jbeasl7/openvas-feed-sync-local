# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10147");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nessus Daemon Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_require_ports("Services/unknown", 1241);
  script_dependencies("find_service2.nasl");

  script_tag(name:"solution", value:"Block those ports from outside communication, or change the
  default port nessus is listening on.");

  script_tag(name:"summary", value:"The port TCP:3001 or TCP:1241 is open, and since this is the default port
  for the Nessus daemon, this usually indicates a Nessus daemon is running,
  and open for the outside world.

  An attacker can use the Nessus Daemon to scan other site, or to further
  compromise the internal network on which nessusd is installed on.
  (Of course the attacker must obtain a valid username and password first, or
  a valid private/public key)");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:1241 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
send( socket:soc, data:string( "TestThis\r\n" ) );
r = recv_line( socket:soc, length:10 );
close( soc );
# We don't want to be fooled by echo & the likes
if( "TestThis" >< r ) {
  set_kb_item( name:"generic_echo_test/" + port + "/failed", value:TRUE );
  exit( 0 );
}

# Used in OpenVAS_detect.nasl so we don't test the same port twice
# with the request above.
set_kb_item( name:"generic_echo_test/" + port + "/tested", value:TRUE );

foreach protocol( make_list( "1.0", "1.2" ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  req = string( "< NTP/", protocol, " >\n" );
  send( socket:soc, data:req );
  res = recv_line( socket:soc, length:20 );
  close( soc );

  if( ereg( pattern:"^< NTP/" + protocol + " >$", string:res ) ) {
    log_message( port:port, data:"A Nessus Daemon is listening on this port." );
    service_register( port:port, proto:"nessus" );
    set_kb_item( name:"nessus/installed", value:TRUE );
  }
  break;
}

exit( 0 );
