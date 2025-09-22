# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900620");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-02 12:54:52 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Zikula / PostNuke Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Zikula / PostNuke.");

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

foreach dir( make_list_unique( "/", "/postnuke", "/PostNuke", "/zikula", "/framework", "/Zikula_Core", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( res && "PostNuke" >< res && egrep( pattern:"<meta name=.generator. content=.PostNuke", string:res, icase:TRUE ) ) {

    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    ver_str = egrep( pattern:"<meta name=.generator. content=.PostNuke", string:res, icase:TRUE );
    ver_str = chomp( ver_str );
    ver = ereg_replace( pattern:".*content=.PostNuke ([0-9].*) .*", string:ver_str, replace:"\1" );
    if( ver == ver_str ) {

      url = dir + "/docs/manual.txt";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );

      if( 'PostNuke' >< res && egrep( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*$", string:res ) ) {
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        ver_str = egrep( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*$", string:res );
        ver_str = chomp( ver_str );
        ver = ereg_replace( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*\(([0-9].*)\)", string:ver_str, replace:"\2" );
        if( ver )
          version = ver;
      }
    }

    set_kb_item( name:"postnuke/detected", value:TRUE );
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:postnuke:postnuke:" );
    if( ! cpe )
      cpe = "cpe:/a:postnuke:postnuke";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"PostNuke",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver_str ),
                                              port:port );
    exit( 0 );
  }

  url = dir + "/docs/distribution/tour_page1.htm";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  res2 = http_get_cache( item:dir + "/index.php", port:port );
  res3 = http_get_cache( item:dir + "/", port:port );

  if( ( res =~ "^HTTP/1\.[01] 200" && ( "congratulations and welcome to Zikula" >< res || 'at <a href="http://community.zikula.org">community.zikula.org</a>.</p>' >< res ) ) ||
      ( res2 =~ "^HTTP/1\.[01] 200" && egrep( pattern:'(Powered by .*Zikula|a href="http://www\\.zikula\\.org">Zikula</a></p>)', string:res2 ) ) ||
      ( res3 =~ "^HTTP/1\.[01] 200" && egrep( pattern:'(Powered by .*Zikula|a href="http://www\\.zikula\\.org">Zikula</a></p>)', string:res3 ) ) ) {

    version = "unknown";

    ver = eregmatch( pattern:"welcome to Zikula ([0-9.]+)", string:res );
    if( ver[1] ) {
      version = ver[0];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    } else {
      url = dir + "/docs/CHANGELOG";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );
      ver = eregmatch( pattern:"ZIKULA ([0-9.]+)", string:res, icase:FALSE );
      if( ver[1] ) {
        version = ver[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"zikula/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zikula:zikula_application_framework:" );
    if( ! cpe )
      cpe = "cpe:/a:zikula:zikula_application_framework";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Zikula",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
