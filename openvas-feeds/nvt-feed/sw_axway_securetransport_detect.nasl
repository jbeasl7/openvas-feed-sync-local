# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111019");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-22 08:00:00 +0200 (Wed, 22 Apr 2015)");
  script_name("Axway SecureTransport Detection");

  script_tag(name:"summary", value:"Detection of the installation and version
  of a Axway SecureTransport.

  The script sends HTTP GET requests and tries to confirm the Axway SecureTransport
  installation and version from the responses.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );
res = http_get_cache( item:"/", port:port );

axwayVer = 'unknown';

# Server: SecureTransport 5.2.1 (build: 1327)
if( concluded = eregmatch( string: banner, pattern: "Server: SecureTransport[/ ]?([0-9.]+?)", icase:TRUE ) ) {
  if( concluded[1] && version_is_greater_equal( version:concluded[1], test_version:"5.0" ) ) {
    installed = 1;
    axwayVer = concluded[1];
  }
}

if( res && ( "<title>Axway SecureTransport Login" >< res || "<title>Axway SecureTransport | Login" >< res) ) {

  ver = eregmatch( pattern:'"SecureTransport", "([0-9.]+)"', string:res );

  if( ver[1] ) {
    axwayVer = ver[1];
    concluded = ver;
  }

  installed = 1;
}

if( installed ) {

  set_kb_item( name:"axway_securetransport/installed", value:TRUE );

  cpe = build_cpe( value:axwayVer, exp:"([0-9a-z.]+)", base:"cpe:/a:axway:securetransport:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:axway:securetransport';

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  log_message( data: build_detection_report( app:"Axway SecureTransport",
                                             version:axwayVer,
                                             install:"/",
                                             cpe:cpe,
                                             concluded:concluded[0] ),
               port:port );
}

exit( 0 );
