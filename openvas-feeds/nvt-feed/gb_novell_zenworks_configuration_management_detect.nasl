# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105252");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-04-10 20:08:50 +0200 (Fri, 10 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Novell ZENworks Control Center Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Novell ZENworks Control Center.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

foreach dir( make_list_unique( "/zenworks", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/jsp/fw/internal/Login.jsp";
  buf = http_get_cache( port:port, item:url );

  if( buf =~ "^HTTP/1\.[01] 200" &&
    ( buf =~ "<title> *Novell *ZENworks *Control *Center[^<]*</title>" || "ZENworks Control Center requires" >< buf ||
    ( "Path=/zenworks/" >< buf && "Server: Apache-Coyote" >< buf  ) ) ) {

    set_kb_item( name:"novell/zenworks_configuration_management/detected", value:TRUE );
    set_kb_item( name:"novell/zenworks_configuration_management/http/detected", value:TRUE );

    cpe = "cpe:/a:novell:zenworks_configuration_management";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Novell ZENworks Control Center",
                                               version:"unknown",
                                               install:install,
                                               cpe:cpe ),
                 port:port );

    exit(0);
  }
}

exit( 0 );
