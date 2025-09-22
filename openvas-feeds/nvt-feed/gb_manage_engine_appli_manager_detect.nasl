# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808054");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-23 10:45:33 +0530 (Mon, 23 May 2016)");

  script_name("ZOHO ManageEngine Applications Manager Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of ZOHO ManageEngine Applications
  Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_require_ports("Services/www", 9090);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:9090 );

foreach dir( make_list_unique( "/", "/manageengine", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.do";
  res = http_get_cache( port:port, item:url );

  if( "manageengine" >< res && '<title>Applications Manager Login Screen</title>' >< res ) {
    version = "unknown";
    concluded = 'URL:     ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"\?build=([0-9]+)", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      concluded += '\nBuild:   ' + vers[0];
    } else {
      # Applications Manager (Build No:14260)
      vers = eregmatch( pattern:"Build No:([0-9]+)", string:res );
      if( ! isnull( vers[1] ) )
        version = vers[1];
        concluded += '\nBuild:   ' + vers[0];
    }

    set_kb_item(name: "manageengine/products/detected", value: TRUE);
    set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
    set_kb_item(name: "zohocorp/manageengine_applications_manager/detected", value: TRUE);
    set_kb_item(name: "zohocorp/manageengine_applications_manager/http/detected", value: TRUE);

    cpe = build_cpe( value:version, exp:"^([0-9]+)", base:"cpe:/a:zohocorp:manageengine_applications_manager:" );
    if( ! cpe )
      cpe = "cpe:/a:zohocorp:manageengine_applications_manager";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"ZOHO ManageEngine Applications Manager", version:version,
                                              install:install, cpe:cpe, concluded:concluded ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
