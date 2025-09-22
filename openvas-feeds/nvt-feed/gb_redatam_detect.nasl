# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141196");
  script_version("2023-12-22T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-12-22 16:09:03 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-06-19 13:09:25 +0700 (Tue, 19 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Redatam Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Redatam.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_mandatory_keys("Host/runs_windows");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://redatam.org/redatam/en/index.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/redbin/RpWebUtilities.exe";
res = http_get_cache(port: port, item: url);

# <h1>Redatam WebUtilities Default Action</h1>
# <h1>R+SP WebUtilities Default Action</h1>
if (res =~ "^HTTP/1\.[01] 200" && egrep(string: res, pattern: "<h1>(R\+SP|Redatam) WebUtilities Default Action</h1>", icase: FALSE)) {
  version = "unknown";
  install = "/redbin";
  conclUrl = http_report_vuln_url(url: url, port: port, url_only: TRUE);

  set_kb_item(name: "redatam/installed", value: TRUE);
  set_kb_item(name: "redatam/detected", value: TRUE);
  set_kb_item(name: "redatam/http/detected", value: TRUE);

  cpe = "cpe:/a:redatam:redatam";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Redatam", version: version, install: install, cpe: cpe, concludedUrl: conclUrl),
              port: port);
}

exit(0);
