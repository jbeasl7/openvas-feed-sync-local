# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801112");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("linkSpheric Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of linkSpheric.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/linkSpheric", "/Spheric", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/admin/index.php", port:port );
  rcvRes2 = http_get_cache( item: dir + "/index.php", port:port );

  if( ( rcvRes =~ "^HTTP/1\.[01] 200" && ( 'generator" content="linkSpheric' >< rcvRes || ( "Powered by" >< rcvRes && "S</span>pheric" >< rcvRes ) ) ) ||
      ( rcvRes2 =~ "^HTTP/1\.[01] 200" && ( 'generator" content="linkSpheric' >< rcvRes2 || ( "Powered by" >< rcvRes2 && "S</span>pheric" >< rcvRes2 ) ) ) ) {

    version = eregmatch( pattern:"linkSpheric version ([0-9.]+( Beta [0-9.])?)", string:rcvRes, icase:1 );
    if( isnull( version ) ) {

      sndReq = http_get( item:dir + "/CHANGELOG", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
      version = egrep( pattern:"version [0-9.]+[a-z0-9 ]+(release)", string:rcvRes, icase:1 );
      version = eregmatch( pattern:"version ([0-9.]+( Beta [0-9])?)", string:version, icase:1 );
    }
    spheric_ver = ereg_replace( pattern:" ", replace:".", string:version[1] );

    if( ! isnull( spheric_ver ) ) {
      version = spheric_ver;
    } else {
      version = "unknown";
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/linkSpheric", value:tmp_version );
    set_kb_item( name:"linkspheric/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)\.([0-9a-zA-Z.]+)", base:"cpe:/a:dataspheric:linkspheric:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:dataspheric:linkspheric';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"linkSpheric",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:spheric_ver ),
                                              port:port );
  }
}

exit( 0 );
