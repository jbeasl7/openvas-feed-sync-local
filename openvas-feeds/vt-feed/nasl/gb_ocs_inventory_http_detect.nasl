# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902058");
  script_version("2026-05-08T16:04:57+0000");
  script_tag(name:"last_modification", value:"2026-05-08 16:04:57 +0000 (Fri, 08 May 2026)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OCS Inventory Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of OCS Inventory.");

  script_xref(name:"URL", value:"https://ocsinventory-ng.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/ocsreports", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache( port:port, item:url );

  if( res =~ "^HTTP/1\.[01] 200" && "OCS Inventory" >< res && "ACTION_CLIC" >< res ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"ocs_inventory/detected", value:TRUE );
    set_kb_item( name:"ocs_inventory/http/detected", value:TRUE );

    vers = eregmatch( pattern:"Ver. (<?.>)?([0-9.]+)", string:res );
    if( ! isnull( vers[2] ) ) {
      version = vers[2];
    } else {
      url = dir + "/Changes";

      res = http_get_cache( port:port, item:url );

      # Revision history for ocsreports
      # 2.7
      vers = eregmatch( pattern:'Revision history for ocsreports[^0-9]+([0-9.]+)[^\r\n]*', string:res );
      if( ! isnull( vers[1] ) ) {
        version = chomp( vers[1] );
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                            desc:"OCS Inventory Detection (HTTP)" );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ocsinventory-ng:ocs_inventory_ng:" );
    if( ! cpe )
      cpe = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"OCS Inventory NG", version:version, install:install,
                                              cpe:cpe, concluded:vers[0], concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
