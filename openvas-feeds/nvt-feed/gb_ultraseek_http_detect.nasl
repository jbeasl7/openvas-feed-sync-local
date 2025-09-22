# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119071");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-21 12:57:18 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Infoseek / Verity Ultraseek Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8765);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Infoseek / Verity Ultraseek (formerly
  Inktomi Search).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:8765 );

banner = http_get_remote_headers( port:port );

# Server: Ultraseek
# <h3>Verity Ultraseek 5.3.1</h3>
# <title>About Verity Ultraseek</title>
bannerpattern = "^[Ss]erver\s*:\s*Ultraseek";
fullpattern = "(" + bannerpattern + "|<h[0-9]+>(Verity|Infoseek) Ultraseek[^<]*<|<title>About (Verity|Infoseek) Ultraseek</title>)";

if( banner = egrep( string:banner, pattern:bannerpattern, icase:FALSE ) ) {
  found = TRUE;
  concluded = "  " + chomp( banner );
  conclUrl = "  " + http_report_vuln_url( port:port, url:"/", url_only:TRUE );
}

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/help/copyright.html";

  if( ! res = http_get_cache( item:url, port:port ) )
    continue;

  if( concl = egrep( string:res, pattern:fullpattern, icase:FALSE ) ) {

    found = TRUE;

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    concl_split = split( concl, keep:FALSE );
    foreach _concl( concl_split ) {
      if( concl = eregmatch( string:_concl, pattern:fullpattern, icase:FALSE ) ) {
        if( concluded )
          concluded += '\n';
        concluded += "  " + concl[0];
      }
    }
    break;
  }
}

if( found ) {

  install = "/";
  version = "unknown";

  set_kb_item( name:"ultraseek/detected", value:TRUE );
  set_kb_item( name:"ultraseek/http/detected", value:TRUE );

  # nb: See example above
  vers = eregmatch( pattern:"<h[0-9]+>(Verity|Infoseek) Ultraseek ([0-9.]+)", string:res, icase:TRUE );
  if( vers[2] )
    version = vers[2];

  # nb: NVD has some inconsistencies around the used CPE
  cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:verity:ultraseek:" );
  cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:infoseek:ultraseek_server:" );
  cpe3 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:verity:verity_ultraseek:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:verity:ultraseek";
    cpe2 = "cpe:/a:infoseek:ultraseek_server";
    cpe3 = "cpe:/a:verity:verity_ultraseek";
  }

  register_product( cpe:cpe1, location:install, port:port, service:"www" );
  register_product( cpe:cpe2, location:install, port:port, service:"www" );
  register_product( cpe:cpe3, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Infoseek / Verity Ultraseek",
                                            version:version,
                                            install:install,
                                            cpe:cpe1,
                                            concluded:concluded,
                                            concludedUrl:conclUrl ),
               port:port );
}

exit( 0 );
