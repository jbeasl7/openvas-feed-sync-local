# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807265");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-17 09:47:57 +0530 (Wed, 17 Feb 2016)");
  script_name("Atlassian Bamboo Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8085, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Atlassian Bamboo.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
found = FALSE;

## There exists a couple of different parameters after 'userlogin', so we're going to check both.
creds = make_list("/userlogin!default.action", "/userlogin!doDefault.action");

foreach dir( make_list_unique( "/", "/bamboo", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach cred( creds ) {
    sndReq = http_get( item:dir + cred, port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if ( rcvRes && "title>Log in as a Bamboo user" >< rcvRes ) {
      found = TRUE;
      break;
    }
  }

  if( found ) {

    version = "unknown";

    ver = eregmatch( pattern:'version ([0-9.]+)( build ([0-9]+))?', string:rcvRes );
    if( ver[1] ) version = ver[1];
    if( ver[3] ) build = "Build: " + ver[3];

    set_kb_item( name:"AtlassianBamboo/Installed", value:TRUE );
    set_kb_item( name:"www/" + port + "/AtlassianBamboo", value:version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:atlassian:bamboo:" );
    if( ! cpe )
      cpe= "cpe:/a:atlassian:bamboo";

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"Atlassian Bamboo",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0],
                                              extra:build),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
