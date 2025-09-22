# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114031");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-11 12:04:27 +0200 (Tue, 11 Sep 2018)");
  script_name("Canon Network Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Canon Network Camera.

  This script sends an HTTP GET request and tries to ensure the presence of
  Canon network Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/-wvhttp-01-/info.cgi";
res = http_get_cache(port: port, item: url);

if("The request requires user authentication." >< res || "Unauthorized" >< res) {
  url = "/";
  res = http_get_cache(port: port, item: url);
}

if("hardware:=" >< res || "type:=" >< res || "firmware:=" >< res || ('<a href="/viewer/admin/en/admin.html">Admin Viewer</a>' >< res && "Network Camera" >< res)) {

  version = "unknown";

  set_kb_item(name: "canon/network_camera/detected", value: TRUE);
  set_kb_item(name: "canon/network_camera/" + port + "/detected", value: TRUE);

  #firmware:=1.0.2
  ver = eregmatch(pattern: "firmware:=([Vv]er. )?([0-9.]+)", string: res);
  if(ver[2]) version = ver[2];

  set_kb_item(name: "canon/network_camera/version", value: version);

  #hardware:=Canon VB-M40
  mod = eregmatch(pattern: "hardware:=Canon ([a-zA-Z0-9-]+)|type:=Canon ([a-zA-Z0-9-]+)|Network Camera ([a-zA-Z0-9-]+)", string: res);
  if(mod[1]) model = mod[1];
  else if(mod[2]) model = mod[2];
  else if(mod[3]) model = mod[3];

  if(model) set_kb_item(name: "canon/network_camera/model", value: model);

  cpe = "cpe:/a:canon:network_camera:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Canon Network Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
