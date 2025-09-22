# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111078");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-01-17 09:00:00 +0100 (Sun, 17 Jan 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("XenForo Forum Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://xenforo.com/");

  script_tag(name:"summary", value:"This script detects an installed XenForo Forum.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/forum", "/forums", "/xenforo", "/xf", "/board", "/boards", http_cgi_dirs( port:port ) ) ) {

  found = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( ">Forum software by XenForo" >< res || "jQuery.extend(true, XenForo," >< res ) ) {
    found = TRUE;
  } else {
    res = http_get_cache(item:dir + "/", port:port );
    if( res =~ "^HTTP/1\.[01] 200" && ( ">Forum software by XenForo" >< res || "jQuery.extend(true, XenForo," >< res ) ) {
      found = TRUE;
    }
  }

  if( found ) {

    # TODO: Try to find an exposed version
    ver = "unknown";

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"xenforo/detected", value:TRUE );

    # CPE not reqistered yet
    cpe = "cpe:/a:xenforo:xenforo";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"XenForo",
                                              version:ver,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
