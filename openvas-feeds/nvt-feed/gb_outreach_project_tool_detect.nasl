# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801069");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Outreach Project Tool Version Detection (OPT)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed Outreach Project Tool version.");

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

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/OPT127MAX/opt", "/opt", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/index.php?OPT_Session=VT_Req", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  if( "<title>Outreach Project Tool Login</title>" >< rcvRes || "./include/opt_css.php" >< rcvRes ||
      'src="main_menu/brief_help/' >< rcvRes || 'src="main_menu/status/"' >< rcvRes ) {

    version = "unknown";

    sndReq = http_get( item: dir + "/include/init_OPT_lib.txt", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if( ! isnull( rcvRes ) && ( ver = egrep( pattern:"CRM_ver.*", string:rcvRes ) ) ) {
      ver = eregmatch( pattern:"([0-9.]+)", string:ver );
      if( ver[1] != NULL ) version = ver[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/OPT", value:tmp_version );
    set_kb_item( name:"outreach_project_tool/detected", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:lanifex:outreach_project_tool:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:lanifex:outreach_project_tool';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Outreach Project Tool",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );
