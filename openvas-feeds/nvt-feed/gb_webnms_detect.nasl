# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105859");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-09 11:21:09 +0200 (Tue, 09 Aug 2016)");
  script_name("WebNMS Framework Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9090);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port( default:9090 );

url = '/LoginPage.do';

req = http_post_put_req( port:port,
                     url:url,
                     data:'supportedBrowser=yes',
                     add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>WebNMS Framework" >!< buf || ( "webnms.com" >!< buf && "Default login details" >!< buf ) ) exit( 0 );

set_kb_item( name:"webnms/installed", value:TRUE );

vers = 'unknown';
cpe = 'cpe:/a:zohocorp:webnms';

version = eregmatch( pattern:'WebNMS Framework ([0-9.]+)', string:buf );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:"/", port:port, service:'www' );

report = build_detection_report( app:"WebNMS Framework", version:vers, install:"/", cpe:cpe, concluded:version[0] );
log_message( port:port, data:report );

exit( 0 );
