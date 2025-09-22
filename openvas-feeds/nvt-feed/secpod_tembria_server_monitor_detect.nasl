# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901107");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_name("Tembria Server Monitor Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the Tembria Server Monitor version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

if( ! http_can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/tembria", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.asp", port:port );

  if( rcvRes =~ "^HTTP/1\.[01] 200" && '>Tembria Server Monitor<' >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:"<version>v([0-9\.]+)</version>", string:rcvRes );
    if( ver[1] ) {
      bver = eregmatch( pattern:"<buildno>([0-9.]+)</buildno>", string:rcvRes );
      if( bver[1] ) {
        version = ver[1] + "." + bver[1];
      } else {
        version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/tembria", value:tmp_version );
    set_kb_item( name:"tembria/server_monitor/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tembria:server_monitor:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:tembria:server_monitor';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Tembria Server Monitor",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
