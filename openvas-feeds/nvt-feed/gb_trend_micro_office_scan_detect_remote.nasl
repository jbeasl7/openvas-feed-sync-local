# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811885");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-02 17:15:23 +0530 (Thu, 02 Nov 2017)");
  script_name("Trend Micro OfficeScan Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443, 4343);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of Trend Micro OfficeScan.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:4343);

req = http_get_req(port:port, url:"/officescan/console/html/help/webhelp/Preface.html");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && res =~ "<title>OfficeScan.*</title>" && "Trend Micro" >< res) {

  version = "unknown";

  MatchVerLine = egrep(pattern:"<title>OfficeScan.*</title>", string:res, icase:TRUE );
  if(MatchVerLine) {
    ver = eregmatch(pattern:' ([0-9.]+)([ SP0-9.]+)?', string:MatchVerLine);
    if(ver[2] && ver[1]) {
      version = ver[1] + ver[2];
    } else {
      version = ver[1];
    }
  }

  set_kb_item( name:"TrendMicro/OfficeScan/Installed/Remote", value:TRUE );
  cpe = build_cpe(value:version, exp:"^([0-9A-Z. ]+)", base:"cpe:/a:trendmicro:officescan:");
  if(!cpe)
    cpe = "cpe:/a:trendmicro:officescan";

  register_product(cpe:cpe, location:"/officescan", port:port, service:"www");

  log_message(data:build_detection_report(app:"Trend Micro OfficeScan",
                                          version:version,
                                          install:"/officescan",
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}

exit(0);
