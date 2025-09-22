# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100466");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SiT! Support Incident Tracker Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SiT! Support Incident Tracker.");

  script_xref(name:"URL", value:"https://sitracker.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( !http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/tracker", "/support", "/sit", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( ( egrep( pattern:'<meta name="GENERATOR" content="SiT! Support Incident Tracker', string:res, icase:TRUE ) &&
    "SiT! - Login" >< res ) ||
    ( "SiT (Support Incident Tracker)" >< res && "sit.js.php" >< res ) ) {

    set_kb_item( name:"sit/detected", value:TRUE );
    set_kb_item( name:"sit/http/detected", value:TRUE );

    version = "unknown";
    vers = eregmatch( string:res, pattern:"Support Incident Tracker v(([0-9.]+).?([a-zA-Z0-9]+))", icase:TRUE );
    if( ! isnull(vers[1] ) ) {
      version = ereg_replace( pattern:" |-", string:vers[1], replace:"." );
      concluded_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:sitracker:support_incident_tracker:" );
    if( ! cpe )
      cpe = "cpe:/a:sitracker:support_incident_tracker";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app: "SiT! Support Incident Tracker", version:version,
                                               install:install, cpe:cpe, concluded:vers[0],
                                               concludedUrl:concluded_url ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
