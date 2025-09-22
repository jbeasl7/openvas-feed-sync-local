# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103483");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-05-04 17:35:57 +0200 (Fri, 04 May 2012)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Symantec Web Gateway Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Symantec Web Gateway.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

symPort = http_get_port(default:80);
if(!http_can_host_php(port:symPort))exit(0);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:symPort ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = string(dir, "/spywall/login.php");
  req = http_get(item:url, port:symPort);
  buf = http_keepalive_send_recv(port:symPort, data:req, bodyonly:FALSE);
  if(!buf) continue;

  if(egrep(pattern: "<title>Symantec Web Gateway - Login", string: buf, icase: TRUE))
  {
    vers = string("unknown");

    version = eregmatch(string: buf, pattern: ">(Version ([0-9.]+))<",icase:TRUE);

    if ( !isnull(version[2]) ) {
      vers=chomp(version[2]);
    }

    set_kb_item(name: string("www/", symPort, "/symantec_web_gateway"), value: string(vers," under ",install));
    set_kb_item(name:"symantec_web_gateway/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:symantec:web_gateway:");
    if(isnull(cpe))
      cpe = 'cpe:/a:symantec:web_gateway';

    register_product(cpe:cpe, location:install, port:symPort, service:"www");

    log_message(data: build_detection_report(app:"Symantec Web Gateway",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded: version[1]),
                                             port:symPort);

  }
}

exit( 0 );
