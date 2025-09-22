# SPDX-FileCopyrightText: 2005 Javier Munoz Mellid
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18185");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Kerio Winroute Firewall Admin Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Javier Munoz Mellid");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(44333);

  script_tag(name:"summary", value:"The administrative interface of a personal firewall is listening
  on the remote port.

  The remote host appears to be running Kerio Winroute Firewall
  Admin service.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

CPE = "cpe:/a:kerio:winroute_firewall:";

include( "host_details.inc" );
include( "port_service_func.inc" );
include( "cpe.inc" );

function kwf_isWeakAdminProtocol( port ) {

  soc = open_sock_tcp(port);

  if( ! soc ) return 0;

  vuln = TRUE;

  for( i = 0; i < 5; i++ ) {

    s = raw_string( 0x01 );
    send( socket:soc, data:s );

    if( ! soc ) vuln = FALSE;

    r = recv( socket:soc, length:16 );

    if( isnull( r ) || ( strlen( r ) != 2 ) || ( ord( r[0] ) != 0x01 ) || ( ord( r[1] ) != 0x00 ) ) {
      vuln = FALSE;
      break;
    }
  }

  close( soc );

  return vuln;
}

port = 44333; # default kwf port
if( ! get_port_state( port ) )
  exit( 0 );

if( kwf_isWeakAdminProtocol( port ) ) {
  set_kb_item( name:"kwf_admin_port/detected", value:TRUE );
  service_register( port:port, proto:"kerio" );
  register_and_report_cpe( app:"Kerio WinRoute Firewall",
                           ver:"unknown",
                           base:CPE,
                           insloc:port + "/tcp",
                           regPort:port,
                           regProto:"tcp" );
}

exit( 0 );
