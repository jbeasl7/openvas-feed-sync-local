# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809485");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-02 16:53:48 +0530 (Fri, 02 Dec 2016)");
  script_name("Disk Savvy Enterprise Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.disksavvy.com");

  script_tag(name:"summary", value:"HTTP based detection of the Disk Savvy Enterprise Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

res = http_get_cache( item:"/login", port:port );

if( "Disk Savvy Enterprise Login" >< res && ">User Name" >< res && ">Password" >< res ) {

  install = "/";
  version = "unknown";

  vers = eregmatch( pattern:">Disk Savvy Enterprise v([0-9.]+)", string:res );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"disk_savvy/enterprise/server/detected", value:TRUE );
  set_kb_item( name:"disk_savvy/enterprise/server/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:disksavvy:disksavvy_enterprise:" );
  if( ! cpe )
    cpe = "cpe:/a:disksavvy:disksavvy_enterprise";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Disk Savvy Enterprise Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
               port:port );
}

exit( 0 );
