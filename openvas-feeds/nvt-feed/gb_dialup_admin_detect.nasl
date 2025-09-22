# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108430");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-03-14 09:41:54 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("dialup_admin Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of dialup_admin interface for the freeradius radius server.

  The script sends a connection request to the server and attempts to detect dialup_admin
  web based administration interface for the freeradius radius server.");

  script_xref(name:"URL", value:"https://github.com/FreeRADIUS/dialup-admin");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/dialup", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  res = http_get_cache( port:port, item:url );

  url2 = dir + "/content.html";
  res2 = http_get_cache( port:port, item:url2 );

  # <title>
  #dialup administration</title>
  if( egrep( string:res, pattern:"dialup administration</title>" ) || egrep( string:res2, pattern:"<b>A web based administration interface for the freeradius radius server</b>" ) ) {

    # Version isn't exposed by the application
    version = "unknown";

    if( install == "/" ) rootInstalled = TRUE;
    set_kb_item( name:"dialup_admin/detected", value:TRUE );
    set_kb_item( name:"dialup_admin/" + port + "/version", value:version );

    cpe = "cpe:/a:freeradius:dialup_admin";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"dialup_admin",
                                              version:version,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}
