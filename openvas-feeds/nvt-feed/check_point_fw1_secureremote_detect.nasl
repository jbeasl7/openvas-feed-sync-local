# SPDX-FileCopyrightText: 2005 SecuriTeam
# SPDX-FileCopyrightText: New / improved code since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10617");
  script_version("2024-06-07T15:38:39+0000");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_dependencies("find_service.nasl", "find_service1.nasl",
                      "find_service2.nasl", "find_service3.nasl");
  script_require_ports("Services/fw1-topology", 256, 264, 18191, 18192);

  script_tag(name:"summary", value:"The remote host seems to be a Check Point FireWall-1 (FW-1)
  running SecureRemote (SecuRemote).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

ports = service_get_ports( default_port_list:make_list( 256, 264, 18191, 18192 ), proto:"fw1-topology" );

foreach port( ports ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  req1 = raw_string( 0x41, 0x00, 0x00, 0x00 );
  req2 = raw_string( 0x02, 0x59, 0x05, 0x21 );

  send( socket:soc, data:req1 );
  send( socket:soc, data:req2 );
  res = recv( socket:soc, length:5 );
  close( soc );

  if( ! res )
    continue;

  reshex = hexstr( res );

  if( res == req1 ||
      # nb:
      # - See find_service1.nasl, find_service2.nasl and find_service3.nasl
      # - For some unknown reason the response within these are two bytes shorter then here
      reshex =~ "^5[19]00000000$" ) {

    version = "unknown";
    build = "unknown";
    report = "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port";

    # nb: Need to open a new connection as we're otherwise seems to get a wrong response
    if( soc = open_sock_tcp( port ) ) {

      # - https://book.hacktricks.xyz/network-services-pentesting/pentesting-264-check-point-firewall-1
      # - https://support.checkpoint.com/results/sk/sk69360
      # - https://web.archive.org/web/20231215170827/https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html#check-point-firewall-1-topology-port-264
      req  = raw_string( 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21 );
      req += raw_string( 0x00, 0x00, 0x00, 0x0b );
      req += "securemote" + raw_string( 0x00 );
      send( socket:soc, data:req );
      res = recv( socket:soc, length:2048 );
      close( soc );

      # e.g.:
      # 0x00:  59 00 00 00 00 00 00 16 43 4E 3D 45 53 31 2C 4F    Y.......CN=ES1,O
      # 0x10:  3D 4D 67 6D 74 2E 2E 62 39 6D 6F 66 66 00 00 00    =Mgmt..b9moff...
      #
      # nb: Currently it is assumed (as no dedicated pattern / separator has been found) that the
      # relevant hostname ends with the first nul char
      if( res && info = eregmatch( string:res, pattern:"CN=([^,]*)\s*,\s*O=([a-zA-Z0-9._-]*)", icase:FALSE ) ) {
        if( info[1] || info[2] )
          report += '.\n\nAdditional info extracted:';

        if( info[1] )
          report += '\n- Firewall Host:    ' + info[1];

        if( info[2] )
          report += '\n- SmartCenter Host: ' + info[2];
      }
    }

    service_register( port:port, proto:"fw1-topology", message:report );
    log_message( port:port, data:report );

    set_kb_item( name:"checkpoint/firewall/detected", value:TRUE );
    set_kb_item( name:"checkpoint/firewall/fw1_topology/detected", value:TRUE );
    set_kb_item( name:"checkpoint/firewall/fw1_topology/port", value:port );
    set_kb_item( name:"checkpoint/firewall/fw1_topology/" + port + "/version", value:version );
    set_kb_item( name:"checkpoint/firewall/fw1_topology/" + port + "/build", value:build );
  }
}

exit( 0 );
