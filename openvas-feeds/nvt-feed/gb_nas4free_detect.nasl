# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105054");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-07-02 14:53:50 +0200 (Wed, 02 Jul 2014)");
  script_name("nas4free Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to detect nas4free from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit (0);

url = "/login.php";
buf = http_get_cache( item:url, port:port );
if( ! buf )
  exit( 0 );

if( "The NAS4Free Project" >< buf && 'title="www.nas4free.org"' >< buf && "username" >< buf && "password" >< buf )
{
  install = "/";
  vers = "unknown";

  set_kb_item(name: string( "www/", port, "/nas4free" ), value: string( vers," under ",install ) );
  set_kb_item(name:"nas4free/installed",value:TRUE);

  cpe = 'cpe:/a:nas4free:nas4free';

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data: build_detection_report( app:"nas4free",
                                             version:vers,
                                             install:install,
                                             cpe:cpe ),
               port:port );
  exit( 0 );
}

exit(0);
