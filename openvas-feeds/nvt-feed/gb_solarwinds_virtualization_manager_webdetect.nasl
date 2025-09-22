# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105766");
  script_version("2024-12-20T05:05:51+0000");
  script_tag(name:"last_modification", value:"2024-12-20 05:05:51 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2016-06-15 21:09:20 +0200 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SolarWinds Virtualization Manager Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SolarWinds Virtualization Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/swvm/ConsoleContainer.jsp";
buf = http_get_cache( item:url, port:port );

if( ! buf || "<title>SolarWinds Virtualization Manager</title>" >!< buf )
  exit( 0 );

cpe = "cpe:/a:solarwinds:virtualization_manager";
version = "unknown";
install = "/swvm";

set_kb_item( name:"solarwinds/virtualization_manager/detected", value:TRUE );
set_kb_item( name:"solarwinds/virtualization_manager/http/detected", value:TRUE );

# ConsoleContainer.swf?version=6.3.1.575
# ConsoleContainer.swf?version=6.3.2.69
vers = eregmatch( pattern:'src="ConsoleContainer\\.swf\\?version=([0-9.]+[^"]+)"', string:buf );
if( ! isnull( vers[1] ) ) {
  parts = split( vers[1], sep:".", keep:FALSE );

  version = parts[0] + "." + parts[1] + "." + parts[2];
  rep_vers = version;

  if( parts[3] ) {
    build = parts[3];
    set_kb_item( name:"solarwinds/virtualization_manager/build", value:build );
    rep_vers += " Build " + build;
  }
}

register_product( cpe:cpe, location:install, port:port, service:"www" );

report = build_detection_report( app:"SolarWinds Virtualization Manager", version:rep_vers, install:install, cpe:cpe, concluded:vers[0] );
log_message( port:port, data:report );
exit( 0 );
