# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103979");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-01 14:27:02 +0200 (Mon, 01 Aug 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Univention Corporate Server (UCS) and Management Console Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script attempts to determine if the target is a Univention
  Corporate Server (UCS). It also tries to detect the Univention Management Console.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

report = ""; # nb: To make openvas-nasl-lint happy...
install = "/";

url = "/ucs-overview/";
req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && ( "<title>Welcome to Univention Corporate Server</title>" >< res ||
                                    ">Welcome to Univention Corporate Server</h1>" >< res ||
                                    'Manual for Univention Corporate Server"></a></li>' >< res ) ) {
  version = "unknown";

  set_kb_item( name:"Univention-Corporate-Server/installed", value:TRUE );

  # CPE not registered / defined yet
  cpe = "cpe:/a:univention:univention_corporate_server";
  register_product( cpe:cpe, location:install, port:port, service:"www" );
  report += build_detection_report( app:"Univention Corporate Server (UCS)",
                                    version:version,
                                    install:install,
                                    cpe:cpe );
  report += '\n\n';
}

url = "/univention-management-console/";
req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && ( "<title>Univention Management Console</title>" >< res ||
                                   '/themes/umc/umc.css" type="text/css"/>' >< res ||
                                   "// set the version of the UMC frontend" >< res ) ) {
  version = "unknown";

  set_kb_item( name:"Univention-Management-Console/installed", value:TRUE );

  # e.g. tools.status('version', '5.0.63-59.1254.201705091107');
  vers = eregmatch( pattern:"tools.status\('version', '([0-9.\-]+)'\);", string:res );
  if( ! isnull( vers[1] ) ) version = vers[1];

  # CPE not registered / defined yet
  cpe = build_cpe( value:version, exp:"^([0-9.\-]+)", base:"cpe:/a:univention:univention_management_console:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:univention:univention_management_console";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  report += build_detection_report( app:"Univention Management Console",
                                    version:version,
                                    install:install,
                                    concluded:vers[0],
                                    cpe:cpe );
}

# Also report the OS once
if( strlen( report ) > 0 ) {
  os_register_and_report( os:"Univention Corporate Server", cpe:"cpe:/o:univention:univention_corporate_server", banner_tpye:"HTTP Login page", port:port, desc:"Univention Corporate Server Detection", runs_key:"unixoide" );
  log_message( port:port, data:report );
}

exit( 0 );
