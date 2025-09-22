# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111071");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-15 19:00:00 +0100 (Tue, 15 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("ComfortableMexicanSofa CMS Engine Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3000);
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

port = http_get_port( default:3000 );
rootInstalled = 0;

foreach dir ( make_list_unique( "/", "/cms", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  if( rootInstalled ) break;

  buf = http_get_cache( item: dir + "/", port:port );

  if( "/system/comfy/cms/files/" >< buf || "/assets/comfy/" >< buf ||
    ( "comfy_admin_cms" >< buf && "comfy/admin/cms/base" >< buf ) ) {

    if( install == "/" ) rootInstalled = 1;
    version = 'unknown';

    #CPE not registered/available yet
    cpe = 'cpe:/a:comfy:comfy';

    set_kb_item( name:"www/" + port + "/comfy", value:version );
    set_kb_item( name:"comfy/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"ComfortableMexicanSofa CMS Engine",
                                               version:version,
                                               install:install,
                                               cpe:cpe),
                                               port:port);
  }
}

exit(0);
