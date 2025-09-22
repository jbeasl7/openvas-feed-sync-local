# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151895");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-11 05:26:53 +0000 (Mon, 11 Mar 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rich Filemanager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Rich Filemanager.");

  script_xref(name:"URL", value:"https://github.com/psolom/RichFilemanager");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 5000);

url = "/";

res = http_get_cache(port: port, item: url);

if ("<title>Rich FileManager</title>" >< res && ".richFilemanager()" >< res) {
  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "rich_filemanager/detected", value: TRUE);
  set_kb_item(name: "rich_filemanager/http/detected", value: TRUE);

  url = "/config/filemanager.config.default.json";

  res = http_get_cache(port: port, item: url);

  # "version": "2.6.1"
  vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  cpe = build_cpe(value: version, epx: "^([0-9.]+)", base: "cpe:/a:psolom:rich_filemanager:");
  if (!cpe)
    cpe = "cpe:/a:psolom:rich_filemanager";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Rich Filemanager", version: version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
