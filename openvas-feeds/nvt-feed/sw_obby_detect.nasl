# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111045");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-05 09:00:00 +0100 (Thu, 05 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("obby Service Detection");

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/obby", 6522);

  script_tag(name:"summary", value:"The script checks the presence of an obby service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = service_get_port( default:6522, proto:"obby" );

soc = open_sock_tcp( port );
if( soc ) {

  send( socket: soc, data: "TEST\r\n\r\n" );

  buf = recv( socket:soc, length:64 );
  close( soc );

  if( banner = egrep( string:buf, pattern:"obby_welcome" ) ) {

    version = "unknown";
    service_register( port:port, proto:"obby" );
    set_kb_item( name:"obby/" + port + "/version", value:version );
    set_kb_item( name:"obby/" + port + "/installed", value:TRUE );

    cpe = "cpe:/a:ubuntu_developers:obby";

    register_product( cpe:cpe, location:port + "/tcp", port:port );

    log_message( data:build_detection_report( app:"obby",
                                              version:version,
                                              install:port + "/tcp",
                                              cpe:cpe,
                                              concluded:banner ),
                                              port:port );
  }
}

exit( 0 );
