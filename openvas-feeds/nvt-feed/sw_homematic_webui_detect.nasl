# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111065");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-09 15:00:00 +0100 (Wed, 09 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("HomeMatic WebUI Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
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
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );

buf = http_get_cache( item: "/index.htm", port:port);

if( sid = eregmatch( pattern:"Location: /index.htm\?sid=@(.*)@", string:buf) ) {

  req = http_get( item: "/pages/index.htm?sid=@" + sid[1] + "@", port:port);
  buf = http_keepalive_send_recv( port:port, data:req );

  if( "<title>HomeMatic WebUI</title>" >< buf ) {

    version = 'unknown';
    location = port + '/tcp';

    ver = eregmatch( pattern:'WEBUI_VERSION = "([0-9.]+)";', string:buf );

    if( ! isnull( ver[1] ) ) version = ver[1];

    #CPE not registered/available yet
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:homematic:homematic_webui:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:homematic:homematic_webui';

    set_kb_item( name:"www/" + port + "/homematic_webui", value:version );
    set_kb_item( name:"homematic_webui/installed", value:TRUE );

    register_product( cpe:cpe, location:location, port:port, service:"www" );

    log_message( data: build_detection_report( app:"HomeMatic WebUI",
                                               version:version,
                                               concluded:ver[0],
                                               install:location,
                                               cpe:cpe),
                                               port:port);
  }
}

exit(0);
