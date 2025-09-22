# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806507");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-10-20 15:07:44 +0530 (Tue, 20 Oct 2015)");

  script_name("Revive Adserver Version Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Revive Adserver.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.revive-adserver.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/adserver", "/radserver", "/revive-adserver", "/ads", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/www/admin/index.php";
  res = http_get_cache( item:url, port:port );
  if( 'Home">Authentication' >!< res || 'content="Revive Adserver' >!< res ) {
    url = dir + "/admin/index.php";
    res = http_get_cache( item:url, port:port );
    if( 'Home">Authentication' >!< res || 'content="Revive Adserver' >!< res )
      continue;
  }

  version = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  ver = eregmatch( pattern:'Revive Adserver v([0-9.]+)', string:res );
  if( ! isnull( ver[1] ) )
    version = ver[1];

  set_kb_item( name:"ReviveAdserver/Installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:revive:adserver:" );
  if( ! cpe )
    cpe = "cpe:/a:revive:adserver";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Revive Adserver", version:version, install:install, cpe:cpe,
                                            concludedUrl:conclUrl, concluded:ver[0] ),
               port:port );
}

exit( 0 );
