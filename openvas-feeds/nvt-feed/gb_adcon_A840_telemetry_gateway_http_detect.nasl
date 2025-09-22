# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105489");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-12-17 16:12:43 +0100 (Thu, 17 Dec 2015)");
  script_name("Adcon A840 Telemetry Gateway Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of a Adcon A840 Telemetry Gateway.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

buf =  http_get_cache( item:"/", port:port );
if( ! buf || "Welcome to the A840 Telemetry Gateway" >!< buf )
  exit( 0 );

set_kb_item( name:"adcon/telemetry_gateway_a840/detected", value:TRUE );
set_kb_item( name:"tg_A840/http/port", value:port );

version = eregmatch( pattern:">Release ([0-9.]+[^,]+),", string:buf );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  set_kb_item( name:"tg_A840/http/version", value:vers );
}

report = "Detected Adcon Telemetry Gateway A840.";
if( vers )
  report += '\nVersion: ' + vers;

log_message( port:port, data:report );

exit( 0 );
