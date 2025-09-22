# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100324");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("TFTgallery Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.tftgallery.org/");

  script_tag(name:"summary", value:"HTTP based detection of TFTgallery.");

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

foreach dir( make_list_unique( "/gallery", "/photos", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf )
    continue;

  # TFT Gallery
  # TFTgallery
  if( concl = egrep( pattern:'<meta name="generator" content="TFT\\s*Gallery', string:buf, icase:TRUE ) ) {

    concl = "  " + chomp( concl );
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    version = "unknown";

    vers = eregmatch( string:buf, pattern:"TFT\s*Gallery ([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name:"tftgallery/detected", value:TRUE );
    set_kb_item( name:"tftgallery/http/detected", value:TRUE );

    register_and_report_cpe( app:"TFTgallery",
                             ver:version,
                             conclUrl:conclUrl,
                             concluded:concl,
                             base:"cpe:/a:tftgallery:tftgallery:",
                             expr:"^([0-9.]+)",
                             insloc:install,
                             regPort:port );
    exit( 0 );
  }
}

exit( 0 );
