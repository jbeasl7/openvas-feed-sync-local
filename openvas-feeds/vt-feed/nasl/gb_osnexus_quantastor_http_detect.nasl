# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140332");
  script_version("2026-08-28T19:34:25+0000");
  script_tag(name:"last_modification", value:"2026-08-28 19:34:25 +0000 (Fri, 28 Aug 2026)");
  script_tag(name:"creation_date", value:"2017-08-29 12:17:34 +0700 (Tue, 29 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OSNEXUS QuantaStor Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of OSNEXUS QuantaStor.");

  script_xref(name:"URL", value:"https://www.osnexus.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if (res =~ "<title>OS\s*NEXUS QuantaStor" >< res && 'href="QuantaStor.css' >< res) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "osnexus/quantastor/detected", value: TRUE);
  set_kb_item(name: "osnexus/quantastor/http/detected", value: TRUE);

  vers = eregmatch(pattern: 'name="qsversion" content="([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:osnexus:quantastor:");
  if (!cpe)
    cpe = "cpe:/a:osnexus:quantastor";

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "OSNEXUS QuantaStor Detection (HTTP)");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "OSNEXUS QuantaStor", version: version, install: location,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
