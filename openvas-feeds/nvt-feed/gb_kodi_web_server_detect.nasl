# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808282");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-08 18:13:32 +0530 (Mon, 08 Aug 2016)");
  script_name("Kodi Web Server Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Kodi Web Server.

  This script sends an HTTP GET request and tries to ensure the presence of
  Kodi Web Server from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port( default:8080 );
res  = http_get_cache( port:port, item:"/" );

if( ( "<title>Kodi</title>" >< res && ">Profiles<" >< res &&
      ">Remote<" >< res && ">Music<" >< res ) ||
    ( "Kodi web interface</title>" >< res && 'js/kodi-webinterface.js"></script>' >< res ) ) {

  version = "unknown";
  install = "/";

  data = '[{"jsonrpc":"2.0","method":"Application.GetProperties","params":[["volume","muted","version"]],"id":71}]';
  url  = "/jsonrpc?Application.GetProperties";

  req = http_post_put_req( port:port, url:url, data:data,
                       accept_header:"text/plain, */*; q=0.01",
                       add_headers:make_array( "Content-Type", "application/json" ) );
  res = http_keepalive_send_recv( port:port, data:req );

  # version":{"major":17,"minor":6
  vers = eregmatch( pattern: 'version".."major":([0-9]+),"minor":([0-9]+)', string:res );
  if( ! isnull( vers[1] ) && ! isnull( vers[2] ) ) {
    version = vers[1] + '.' + vers[2];
    set_kb_item( name:"Kodi/WebServer/version", value:version );
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  set_kb_item( name:"Kodi/WebServer/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kodi:kodi:");
  if( ! cpe )
    cpe = "cpe:/a:kodi:kodi";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Kodi Web Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0],
                                            concludedUrl:conclUrl ),
                                            port:port );
}

exit( 0 );
