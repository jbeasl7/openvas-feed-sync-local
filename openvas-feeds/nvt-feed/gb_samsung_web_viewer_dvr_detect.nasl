# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114046");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-12 19:06:20 +0100 (Mon, 12 Nov 2018)");
  script_name("Samsung Web Viewer DVR Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of Samsung Web Viewer DVR.

  This script sends an HTTP GET request and tries to ensure the presence of
  Samsung Web Viewer DVR.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/js/language_webviewer.js";
res = http_get_cache(port: port, item: url);
if(res =~ "<h1>404\s*-\s*Not Found</h1>") {
  url = "/cgi-bin/webviewer_login_page?lang=en&loginvalue=0&port=0";
  res = http_get_cache(port: port, item: url);
}

if(res =~ '\\[\\s*"Web Viewer for Samsung DVR' || ('/language_webviewer.js"></script>' >< res && "function setcookie(){" >< res)) {

  version = "unknown";

  set_kb_item(name: "samsung/web_viewer/dvr/detected", value: TRUE);
  set_kb_item(name: "samsung/web_viewer/dvr/" + port + "/detected", value: TRUE);

  cpe = "cpe:/a:samsung:web_viewer_dvr:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Samsung Web Viewer DVR",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl);
}

exit(0);
