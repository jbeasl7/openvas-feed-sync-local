# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141285");
  script_version("2024-11-07T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-07-10 08:56:51 +0200 (Tue, 10 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine Exchange Reporter Plus Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine Exchange Reporter Plus.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/exchange-reports/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8181);

url = "/exchange/Home.do";

res = http_get_cache(port: port, item: url);
if ("<title>ManageEngine - Exchange Reporter Plus</title>" >!< res || "Exchange services" >!< res) {
  url = "/exchange/AppsHome.do";
  res = http_get_cache(port: port, item: url);
  if ("<title>ManageEngine - Exchange Reporter Plus</title>" >!< res || "Exchange services" >!< res)
    exit(0);
}

version = "version";
location = "/";
concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

# js/div-util.js?v=5704
vers = eregmatch(pattern: "\.js\?v=([0-9]+)", string: res);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "manageengine/products/detected", value: TRUE);
set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
set_kb_item(name: "manageengine/exchange_reporter_plus/detected", value: TRUE);
set_kb_item(name: "manageengine/exchange_reporter_plus/http/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:zohocorp:manageengine_exchange_reporter_plus:");
if (!cpe)
  cpe = "cpe:/a:zohocorp:manageengine_exchange_reporter_plus";

os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                       desc: "ManageEngine Exchange Reporter Plus Detection (HTTP)", runs_key: "windows");

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "ManageEngine Exchange Reporter Plus", version: version,
                                         install: location, cpe: cpe, concluded: vers[0],
                                         concludedUrl: concUrl),
            port: port);
exit(0);
