# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800170");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_name("MoinMoin Wiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of MoinMoin Wiki.

  This script detects the installed version of MoinMoin Wiki.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

function _SetCpe( vers, port, dir, concl, conclUrl ) {

  local_var vers, port, tmp_version, dir, concl, conclUrl;

  tmp_version = vers + " under " + dir;
  set_kb_item( name:"www/" + port + "/moinmoinWiki", value:tmp_version );
  set_kb_item( name:"moinmoinWiki/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.a-z]+)", base:"cpe:/a:moinmo:moinmoin:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:moinmo:moinmoin';

  register_product( cpe:cpe, location:dir, port:port, service:"www" );
  log_message( data:build_detection_report( app:"moinmoinWiki",
                                            version:vers,
                                            install:dir,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:concl ),
                                            port:port );
}

port = http_get_port( default:8080 );

banner = http_get_remote_headers( port:port );
if( "erver: MoinMoin" >< banner ) {
  bannerIdentified = TRUE;
  vers = eregmatch( pattern:"erver: MoinMoin ([0-9.a-z]+) release", string:banner );
  if( vers[1] ) {
    bannerVersion = TRUE;
    _SetCpe( vers:vers[1], port:port, dir:"/", concl:vers[0] );
  }
}

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/Moin", "/moin", "/wiki", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  if( rootInstalled ) break;

  url1 = dir + "/SystemInfo";
  req1 = http_get( item:url1, port:port );
  res1 = http_keepalive_send_recv( port:port, data:req1 );

  res2 = http_get_cache( item:"/", port:port );

  if( ( res1 =~ "^HTTP/1\.[01] 200" && "SystemInfo" >< res1 && ">MoinMoin" >< res1 ) ||
        "This site uses the MoinMoin Wiki software." >< res2 || ">MoinMoin Powered<" >< res2 ) {

    version = "unknown";
    flag = TRUE;
    if( install == "/" ) rootInstalled = TRUE;
    if( bannerVersion && install == "/" ) continue;

    vers = eregmatch( pattern:"(Release|Version) ([0-9.a-z]+) \[Revision release\]", string:res1 );
    if( vers[2] ) {
      version  = vers[2];
      conlcUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
    } else {
      # MoinMoin/config/__init__.py:url_prefix_static = '/moin_static' + version.release_short
      # so we can conclude the version from css/js links like:
      # <link rel="stylesheet" type="text/css" charset="utf-8" media="all" href="/moin_static194/modern/css/common.css">
      vers = eregmatch( pattern:'(src|href)="/moin_static([0-9]+)/', string:res2 );
      if( vers[2] ) {
        short_vers = vers[2];
        for( i = 0; i < strlen( short_vers ); i++ ) {
          if( i == 0 ) {
            version = short_vers[i];
          } else {
            version += "." + short_vers[i];
          }
        }
      }
    }
    _SetCpe( vers:version, port:port, dir:install, concl:vers[0], conclUrl:conlcUrl );
  }
}

if( bannerIdentified && ! flag ) {
  _SetCpe( vers:version, port:port, dir:install, concl:vers[0] );
}

exit( 0 );
