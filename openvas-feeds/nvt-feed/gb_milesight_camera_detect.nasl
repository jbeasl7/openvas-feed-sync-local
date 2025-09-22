# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113230");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-17 13:40:00 +0200 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Milesight Network Camera Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detect Milesight Network Cameras.");

  script_xref(name:"URL", value:"http://www.milesight.com/");

  exit(0);
}

CPE = "cpe:/h:milesight:network_camera:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 8080 );

buf = http_get_cache( port: port, item: "/" );

if( "<title>Milesight Network Camera</title>" >< buf ||
    "http://www.milesight.com/UploadFiles/VMS/camview.dmg" >< buf ) {

  set_kb_item( name: "milesight/network_camera/detected", value: TRUE );
  set_kb_item( name: "milesight/network_camera/ui_port", value: port );

  register_and_report_cpe( app: "Milesight Network camera",
                           ver: "unknown",
                           expr: "([0-9.]+)",
                           base: CPE,
                           insloc: "/",
                           regPort: port );
}

exit( 0 );
