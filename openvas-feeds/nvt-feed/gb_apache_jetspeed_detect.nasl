# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807647");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:25 +0530 (Fri, 01 Apr 2016)");
  script_name("Apache Jetspeed Detection");

  script_tag(name:"summary", value:"Detection of Apache Jetspeed Open Portal.
  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/jetspeed", "/jetspeed/portal", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache( item:dir + "/", port:port );

  if( 'Welcome to Jetspeed' >< rcvRes && 'Login Portlet' >< rcvRes ) {

    version = "unknown";

    url = dir + "/about.psml";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    ver = eregmatch( pattern:"<h2>About the Jetspeed ([0-9.]+) Release</h2>", string:buf );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"www/" + port + "/jetspeed", value:version );
    set_kb_item( name:"Jetspeed/Installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:jetspeed:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:apache:jetspeed";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Apache Jetspeed",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
    exit(0);
  }
}
exit( 0 );
