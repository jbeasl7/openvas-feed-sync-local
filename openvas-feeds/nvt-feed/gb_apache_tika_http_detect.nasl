# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810251");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Tika Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Tika.");

  script_xref(name:"URL", value:"https://tika.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9998);

url = "/";
res = http_get_cache(port: port, item: url);

if ("<title>Welcome to the Apache Tika" >!< res &&
    ("Apache Tika" >!< res || "For endpoints, please see" >!< res)) {
  url = "/version";

  res = http_get_cache(port: port, item: url);

  if (res !~ "(Apache )?Tika [0-9.]+")
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "apache/tika/detected", value: TRUE);
set_kb_item(name: "apache/tika/http/detected", value: TRUE);

# <title>Welcome to the Apache Tika 3.2.2 Server</title>
vers = eregmatch(pattern: "Welcome to the Apache Tika ([0-9.]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  if (url >!< conclUrl)
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
} else {
  url = "/version";

  res = http_get_cache(port: port, item: url);

  # Apache Tika 3.2.2
  # Tika 3.0.0
  vers = eregmatch(pattern: "(Apache )?Tika ([0-9.]+)", string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    if (url >!< conclUrl)
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
}


cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:tika:");
if (!cpe)
  cpe = "cpe:/a:apache:tika";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data:build_detection_report(app: "Apache Tika Server", version: version, install: location,
                                        cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
            port:port);

exit(0);
