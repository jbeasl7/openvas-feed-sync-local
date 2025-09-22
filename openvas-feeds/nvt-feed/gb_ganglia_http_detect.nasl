# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103534");
  script_version("2024-11-28T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-28 05:05:41 +0000 (Thu, 28 Nov 2024)");
  script_tag(name:"creation_date", value:"2012-08-13 12:20:02 +0200 (Mon, 13 Aug 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ganglia Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Ganglia.");

  script_xref(name:"URL", value:"https://github.com/ganglia/ganglia-web");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/ganglia", "/gang", "/gweb", "/ganglia-web", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( port:port, item:url );
  if( ! res )
    continue;

  if( ( "<title>ganglia" >< tolower( res ) && "Ganglia Web Backend" >< res) ||
        "There was an error collecting ganglia data" >< res ) {
    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"Ganglia Web Frontend version ([0-9.]+)", string:res, icase:TRUE );

    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name:"ganglia/detected", value:TRUE );
    set_kb_item( name:"ganglia/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ganglia:ganglia-web:" );
    if( ! cpe )
      cpe = "cpe:/a:ganglia:ganglia-web";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Ganglia", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
