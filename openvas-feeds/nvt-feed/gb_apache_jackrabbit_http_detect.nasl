# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807896");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-10-06 14:29:25 +0530 (Thu, 06 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Jackrabbit Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Jackrabbit.");

  script_xref(name:"URL", value:"https://jackrabbit.apache.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

url = "/";

res = http_get_cache(port: port, item: url);

if (">Jackrabbit JCR Server" >< res && "jackrabbit.apache.org" >< res) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  url = "/server";

  res = http_get_cache(port: port, item: url);

  # >Jackrabbit</a> 2.13.1<
  vers = eregmatch(pattern: ">Jackrabbit</a>\s*([0-9.]+)<", string: res);
  if (isnull(vers[1])) {
    url = "/repository/default/";

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: ">Jackrabbit<.*version ([0-9.]+)<", string: res);
  }

  if (vers[1]) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "apache/jackrabbit/detected", value: TRUE);
  set_kb_item(name: "apache/jackrabbit/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:jackrabbit:");
  if (!cpe)
    cpe = "cpe:/a:apache:jackrabbit";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache Jackrabbit", version: version, install: location,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
