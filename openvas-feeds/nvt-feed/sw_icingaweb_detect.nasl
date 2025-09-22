# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111056");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-11-22 13:00:00 +0100 (Sun, 22 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Icinga Web Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request
  to the server and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );

if( !http_can_host_php( port:port ) ) exit( 0 );

foreach dir ( make_list_unique( "/", "/icinga", "/icinga-web", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( eregmatch( pattern:'<title>Icinga</title>', string:buf, icase:TRUE ) ||
      "Icinga Developer Team" >< buf || "Welcome to icinga-web" >< buf ) {

    version = 'unknown';

    ver = eregmatch( pattern:"icinga-web/v([0-9.]+)", string:buf, icase:TRUE );

    if( ! isnull( ver[1] ) ) version = ver[1];

    #CPE not registered/available yet
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:icinga:icingaweb:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:icinga:icingaweb';

    set_kb_item( name:"www/" + port + "/icingaweb", value:version );
    set_kb_item( name:"icingaweb/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Icinga Web",
                                               version:version,
                                               concluded:ver[0],
                                               install:install,
                                               cpe:cpe),
                                               port:port);
  }
}

exit(0);
