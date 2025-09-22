# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100224");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-21 16:51:00 +0200 (Sun, 21 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Webmedia Explorer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.webmediaexplorer.com/");

  script_tag(name:"summary", value:"This host is running Webmedia Explorer, a free Open Source PHP
  engine that reads your hard disc as a conventional disc explorer and
  generates a website realtime taking advantage of a very powerful
  rendering and data fetching caching system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/fileexplorer", "/explorer", "/wme", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php?action=login";

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( isnull( buf ) ) continue;

  if( egrep( pattern:'Powered by <a [^>]+>webmedia explorer', string:buf, icase:TRUE ) &&
      egrep( pattern:"Set-Cookie: dir_stack_cookie", string:buf ) ) {

    version = "unknown";
    vers = eregmatch( string:buf, pattern:"webmedia explorer ([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[1] ) ) version = chomp( vers[1] );

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/WebmediaExplorer", value:tmp_version );
    set_kb_item( name:"WebmediaExplorer/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:webmediaexplorer:webmedia_explorer:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:webmediaexplorer:webmedia_explorer";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Webmedia Explorer",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
