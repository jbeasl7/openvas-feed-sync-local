# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106650");
  script_version("2024-08-23T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-03-14 12:58:36 +0700 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Logsign Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Logsign.");

  script_xref(name:"URL", value:"https://www.logsign.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/login";

res = http_get_cache(port: port, item: url);

if ("<title>Logsign</title>" >!< res || "var global = global" >!< res) {
  url = "/ui/modules/login/";

  res = http_get_cache(port: port, item: url);

  if ("<title>Logsign</title>" >!< res || "/ui/modules/login/css/module.tpl" >!< res)
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "logsign/detected", value: TRUE);
set_kb_item(name: "logsign/http/detected", value: TRUE);

url = "/api/settings/license_status";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

# {"host_id": "<redacted>", "version": "6.4.24", ...
vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)"', string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:logsign:logsign:");
if (!cpe)
  cpe = "cpe:/a:logsign:logsign";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                       desc: "Logsign Detection (HTTP)");

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "Logsign", version: version, install: location, cpe: cpe,
                                         concluded: vers[0], concludedUrl: conclUrl),
            port: port);

exit(0);
