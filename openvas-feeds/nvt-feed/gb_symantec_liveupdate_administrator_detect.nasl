# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804358");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-03 12:20:29 +0530 (Thu, 03 Apr 2014)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Symantec LiveUpdate Administrator Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Symantec LiveUpdate Administrator.

This script sends an HTTP GET request and tries to get the version from the
response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7070);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

luaPort = http_get_port(default:7070);

sndReq = http_get(item: "/lua/onlinehelp/LUHelp0002.html", port:luaPort);
rcvRes = http_send_recv(port:luaPort, data:sndReq, bodyonly:TRUE);

if(rcvRes && "LiveUpdate Administrator<" >< rcvRes)
{
  sndReq = http_get(item: "/lua/logon.do", port:luaPort);
  rcvRes = http_send_recv(port:luaPort, data:sndReq, bodyonly:TRUE);

  if(rcvRes && "lua_title" >< rcvRes && "Symantec Corporation" >< rcvRes)
  {
    luaVer = eregmatch( string:rcvRes, pattern:"Version:.([0-9.]+)", icase:TRUE);

    if(luaVer[1] != NULL)
    {
      set_kb_item(name:"Symantec/LUA/Version", value:luaVer[1]);

      cpe = build_cpe(value:luaVer[1], exp:"^([0-9.]+)", base:"cpe:/a:symantec:liveupdate_administrator:");
      if(!cpe)
        cpe="cpe:/a:symantec:liveupdate_administrator";

      register_product(cpe:cpe, location:"/lua", port:luaPort, service:"www");

      log_message(data: build_detection_report(app: "Symantec LiveUpdate Administrator",
                                               version: luaVer[1],
                                               install: "/lua",
                                               cpe: cpe,
                                               concluded: luaVer[1]), port: luaPort);
    }
  }
}

exit(0);
