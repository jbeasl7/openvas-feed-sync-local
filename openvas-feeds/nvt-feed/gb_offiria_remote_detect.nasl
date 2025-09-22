# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805195");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-06-09 16:51:06 +0530 (Tue, 09 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_name("Offiria Open Source Enterprise Social Network Remote Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Offiria Open Source Enterprise Social Network.

  This script sends an HTTP GET request and tries to confirm the application from
  the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/offiria", "/social", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "^HTTP/1\.[01] 200" && ">Offiria<" >< rcvRes ) {

    ## Not able to get version without login
    ver = "Unknown";

    set_kb_item( name:"offiria/installed", value:TRUE );

    cpe = "cpe:/a:slashes&dots:offria";

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data: build_detection_report( app:"Offiria",
                                               version:ver,
                                               install:install,
                                               cpe:cpe ),
                                               port:port );
  }
}

exit( 0 );
