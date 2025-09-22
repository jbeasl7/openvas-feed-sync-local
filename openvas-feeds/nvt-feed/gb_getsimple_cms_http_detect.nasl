# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801550");
  script_version("2025-01-03T15:39:41+0000");
  script_tag(name:"last_modification", value:"2025-01-03 15:39:41 +0000 (Fri, 03 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("GetSimple CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of GetSimple CMS.");

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
if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/GetSimple", "/getsimple", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( res =~ ">Powered by.*GetSimple<" || "Welcome to GetSimple!" >< res ||
      "<p>&copy; GetSimple CMS" >< res || res =~ ">Copyright.*GetSimple CMS"  ||
      ">GetSimple CMS<" >< res || res =~ 'content="getsimple' ) {

    if( dir == "" )
      rootInstalled = TRUE;

    version = "unknown";

    vers = eregmatch( pattern:"> Version ([0-9a-z.]+)<", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    } else {
      url = dir + "/admin/index.php";
      res = http_get_cache( port:port, item:url );

      # "template/js/jquery.getsimple.js?v=3.3.4"
      vers = eregmatch( pattern:"jquery\.getsimple\.js\?v=([0-9a-z.]+)", string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"getsimple_cms/detected", value:TRUE );
    set_kb_item( name:"getsimple_cms/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9a-z.]+)", base:"cpe:/a:get-simple:getsimple_cms:" );
    if( ! cpe )
      cpe = "cpe:/a:get-simple:getsimple_cms";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"GetSimple CMS", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl:concUrl ),
                 port:port );
  }
}

exit( 0 );
