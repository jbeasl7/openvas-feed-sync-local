# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107366");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-11-12 16:31:12 +0100 (Mon, 12 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ServersCheck Monitoring Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ServersCheck_Monitoring_Server/banner");

  script_tag(name:"summary", value:"HTTP based detection of the ServersCheck Monitoring Server.");

  script_xref(name:"URL", value:"https://serverscheck.com/monitoring-software/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );

if( ! banner || banner !~ "Server\s*:\s*ServersCheck_Monitoring_Server" )
  exit( 0 );

version = "unknown";
set_kb_item( name: "serverscheck/monitoring_server/http/detected", value: TRUE );
set_kb_item( name: "serverscheck/monitoring_software_or_server/detected", value: TRUE );
set_kb_item( name: "serverscheck/monitoring_server/http/port", value: port );

# Server: ServersCheck_Monitoring_Server/1.1
# Server: ServersCheck_Monitoring_Server/14.0
#
# nb: Version of the server banner != the version of the Software
vers = eregmatch( pattern: "ServersCheck_Monitoring_Server/([0-9.]+)", string: banner, icase: TRUE );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name: "serverscheck/monitoring_server/http/version", value: version );
  set_kb_item( name: "serverscheck/monitoring_server/http/concluded", value: vers[0] );
}

register_and_report_cpe( app: "ServersCheck Monitoring Server", ver: version, base: "cpe:/a:serverscheck:monitoring_server:", expr: "^([0-9.]+)", insloc: "/", regPort: port, concluded: vers[0], regService: "www" );
exit( 0 );
