# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900420");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)");
  script_name("MediaWiki Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of MediaWiki.");

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

max_tries = 5;

foreach dir( make_list_unique( "/", "/wiki", "/mediawiki", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php/Special:Version";
  res = http_get_cache( item:url, port:port );

  tries = 0;
  # nb: Follow redirects for different languages, e.g Special:Version -> Especial:Version
  while( res =~ "^HTTP/1\.[01] 30[12]" ) {
    tries += 1;
    if( path = http_extract_location_from_redirect( port:port, data:res, current_dir:install ) ) {
      res = http_get_cache( item:path, port:port );
    }
    if( tries >= max_tries )
      break;
  }

  if( ( res =~ "[Pp]owered by" || res =~ 'name="generator" content="MediaWiki' ) && "MediaWiki" >< res && res =~ "^HTTP/1\.[01] 200" ) {

    version = "unknown";
    ver = eregmatch( pattern:"MediaWiki ([0-9.]+)(.?([a-zA-Z0-9]+))?", string:res );
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    if( ! isnull( ver[1] ) ) {
      if( ! isnull( ver[3] ) ) {
        version = ver[1] + "." + ver[2];
      } else {
        version = ver[1];
      }
    }

    set_kb_item( name:"mediawiki/detected", value:TRUE );
    set_kb_item( name:"mediawiki/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:mediawiki:mediawiki:" );
    if( ! cpe )
      cpe = "cpe:/a:mediawiki:mediawiki";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"MediaWiki",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
