# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100909");
  script_version("2026-05-07T06:32:13+0000");
  script_tag(name:"last_modification", value:"2026-05-07 06:32:13 +0000 (Thu, 07 May 2026)");
  script_tag(name:"creation_date", value:"2010-11-18 13:10:44 +0100 (Thu, 18 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Vtiger CRM Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"HTTP based detection of vtiger CRM.");

  script_xref(name:"URL", value:"https://www.vtiger.com/");

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

foreach dir( make_list_unique( "/vtigercrm", "/crm", "/", "/vt", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache( port:port, item:url );

  if( ( "<title>vtiger CRM" >< res && ( "login_language" >< res || ">Powered by vtiger" >< res ) ) ||
      ( "<title>Vtiger" >< res && "Powered by vtiger CRM" >< res ) ||
      ( "Powered by vtiger CRM" >< res && 'target="_blank">Privacy Policy</a>' >< res ) ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( string:res, pattern:"vtiger CRM[\ ]?+[-]?[\ ]?+([0-9.]+)([^ ]| RC)", icase:TRUE );
    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name:"vtiger/detected", value:TRUE );
    set_kb_item( name:"vtiger/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vtiger:vtiger_crm:" );
    if( ! cpe )
      cpe = "cpe:/a:vtiger:vtiger_crm";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Vtiger CRM", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl: conclUrl ),
                 port:port );
  }
}

exit( 0 );
