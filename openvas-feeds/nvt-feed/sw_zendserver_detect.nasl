# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111028");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-21 18:00:00 +0200 (Fri, 21 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ZendServer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ZendServer/banner");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

phpList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
if(phpList)
  phpFiles = make_list(phpList);

if(phpFiles[0]) {
  banner = http_get_remote_headers(port:port, file:phpFiles[0]);
} else {
  banner = http_get_remote_headers(port:port, file:"/index.php");
}

if( "ZendServer" >!< banner )
  exit( 0 );

version = "unknown";
install = port + "/tcp";

ver = eregmatch( pattern:'(ZendServer|-ZS)(/| |)([0-9.]+)', string:banner );
if( ! isnull( ver[3] ) )
  version = ver[3];

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zend:zend_server:" );
if( ! cpe )
  cpe = "cpe:/a:zend:zend_server";

set_kb_item( name:"www/" + port + "/zendserver", value:version );
set_kb_item( name:"zendserver/installed", value:TRUE );

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"ZendServer",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:ver[0] ),
             port:port );
exit( 0 );
