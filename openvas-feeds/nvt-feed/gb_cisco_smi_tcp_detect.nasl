# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113756");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-10-01 10:11:11 +0200 (Thu, 01 Oct 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Smart Install (SMI) Protocol Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(4786);

  script_tag(name:"summary", value:"TCP based detection of services supporting the Cisco Smart
  Install (SMI) protocol.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("port_service_func.inc");

port = 4786;

if( ! get_port_state( port ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

req =  raw_string( 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
                   0x00
                 );

send( socket: soc, data: req );
recv = recv( socket: soc, length: 20, timeout: 30 );
close( soc );

if( ! recv || strlen( recv ) != 20 )
  exit( 0 );

if( hexstr( recv ) =~ "^0000000400000000000000040000000400000001$" ) {

  os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: "Cisco SMI protocol", port: port, desc: "Cisco Smart Install (SMI) Protocol Detection (TCP)", runs_key: "unixoide" );

  set_kb_item( name: "cisco/smi/detected", value: TRUE );
  set_kb_item( name: "cisco/smi/tcp/detected", value: TRUE );

  service_register( proto: "cisco_smi", port: port );

  report = "A service supporting the Cisco Smart Install (SMI) protocol was detected on the target system.";
  log_message( port: port, data: report );
}

exit( 0 );
