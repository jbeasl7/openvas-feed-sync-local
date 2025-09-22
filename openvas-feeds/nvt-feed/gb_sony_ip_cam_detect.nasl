# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107105");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-09 12:56:26 +0100 (Fri, 09 Dec 2016)");
  script_name("Sony IPELA Engine IP Camera Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Sony IPELA Engine IP Cameras.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8080 );
buf = http_get_cache( port:port, item:"/" );

if( "Sony Network Camera" >!< buf && "SONY Network Camera" >!< buf )
  exit( 0 );

mod = eregmatch( pattern:"[SONY|Sony] Network Camera SNC-([A-Z]+[0-9]+)", string:buf );
if( mod[1] ) {
  model = "SNC-" + mod[1];
} else {
  model = "unknown";
}

set_kb_item( name:"sony/ip_camera/model", value:model );
set_kb_item( name:"sony/ip_camera/installed", value:TRUE );
set_kb_item( name:"sony/ip_camera/http/detected", value:TRUE );
set_kb_item( name:"sony/ip_camera/detected", value:TRUE );

cpe = "cpe:/h:sony:sony_network_camera_snc";

firmVer = eregmatch( pattern:"Server: gen[5|6]th/([0-9.]+)", string:buf );
if( firmVer[1] ) {
  set_kb_item( name:"sony/ip_camera/firmware", value:firmVer[1] );
  cpe += ":" + firmVer[1];
} else {
  set_kb_item( name:"sony/ip_camera/firmware", value:"unknown" );
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = build_detection_report( app:"Sony IP Camera", version:firmVer[1], install:"/", cpe:cpe, extra: "Model: " + model );
log_message( port:port, data:report );

exit( 0 );
