# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802428");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-04-16 13:02:43 +0530 (Mon, 16 Apr 2012)");
  script_name("AppServ Open Project Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.appservnetwork.com/?appserv");

  script_tag(name:"summary", value:"Detection of AppServ Open Project, an open source web
  server.

  The script sends a connection request to the web server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

res = http_get_cache(item: "/", port:port);

if("title>AppServ Open Project" >< res && ">About AppServ" >< res)
{
  appVer = eregmatch(pattern:"AppServ Version ([0-9.]+)" , string:res);
  if(appVer[1] != NULL) {
    set_kb_item(name:"www/" + port + "/AppServ",value:appVer[1]);
  }

  set_kb_item(name:"AppServ/installed", value:TRUE);

  cpe = build_cpe(value:appVer[1], exp:"^([0-9.]+)",
                    base:" cpe:/a:appserv_open_project:appserv:");
  if(isnull(cpe))
    cpe = 'cpe:/a:appserv_open_project:appserv';

  location = string(port, "/http");
  register_product(cpe:cpe, location:location, port:port, service:"www");

  log_message(data:'Detected AppServ Open Project version: ' + appVer[1] +
  '\nLocation: ' + location +
  '\nCPE: '+ cpe +
  '\n\nConcluded from version identification result:\n'
  + appVer[max_index(appVer)-1]);
}

exit(0);
