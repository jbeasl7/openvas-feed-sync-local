# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18177");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Websense Reporting Console Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8010);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"The remote host appears to be running Websense, connections are allowed
  to the web reporting console.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:websense:enterprise";

include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "port_service_func.inc" );
include( "host_details.inc" );
include( "os_func.inc" );
include( "cpe.inc" );

if( os_host_runs("Windows") != "yes" )
  exit( 0 );

port = http_get_port( default: 8010 );

url = "/Websense/cgi-bin/WsCgiLogin.exe";
req = http_get( item: url, port: port );
rep = http_keepalive_send_recv( port: port, data: req );
if( ! rep )
  exit( 0 );

if( "<title>Websense Enterprise - Log On</title>" >< rep ) {
  set_kb_item( name: "websense/enterprise/detected", value: TRUE );
  register_and_report_cpe( app: "Websense Enterprise",
                           ver: "unknown",
                           base: CPE,
                           insloc: port + "/tcp",
                           regPort: port,
                           regProto: "tcp" );
}

exit( 0 );
