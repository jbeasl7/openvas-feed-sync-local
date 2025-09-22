# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111042");
  script_version("2024-04-12T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-04-12 05:05:39 +0000 (Fri, 12 Apr 2024)");
  script_tag(name:"creation_date", value:"2015-10-15 12:00:00 +0200 (Thu, 15 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Magmi (Magento Mass Importer) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "sw_magento_detect.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://wiki.magmi.org");

  script_tag(name:"summary", value:"HTTP based detection of Magmi (Magento Mass Importer).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

# nb: First see if Magento was already detected
port = get_app_port( cpe:CPE, service:"www" );
if( port ) {
  magentoDir = get_app_location( cpe:CPE, port:port );
} else {
  port = http_get_port( default:80 );
}

if( ! http_can_host_php( port:port ) )
  exit( 0 );

if( magentoDir ) {
  if( magentoDir == "/" )
    magentoDir = "";
  dirs = make_list_unique( http_cgi_dirs( port:port ), "/magmi-importer", "/magmi", magentoDir + "/magmi-importer", magentoDir + "/magmi" );
} else {
  dirs = make_list_unique( http_cgi_dirs( port:port ), "/magmi-importer", "/magmi" );
}

foreach dir( dirs ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/web/magmi.php";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  url = dir + "/ReleaseNotes.txt";
  req = http_get( item:url, port:port );
  res2 = http_keepalive_send_recv( port:port, data:req );

  if( '<link rel="stylesheet" href="css/magmi.css"></link>' >< res || "RELEASE NOTES FOR MAGMI" >< res2 ) {

    version = "unknown";

    ver = eregmatch( pattern:"RELEASE NOTES FOR MAGMI ([0-9a-zA-Z.]+)", string:res2 );
    if( ver[1] )
      version = ver[1];

    set_kb_item( name:"magmi/detected", value:TRUE );
    set_kb_item( name:"magmi/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9a-zA-Z.]+)", base:"cpe:/a:magmi_project:magmi:" );
    if( ! cpe )
      cpe = "cpe:/a:magmi_project:magmi";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Magmi (Magento Mass Importer)",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
