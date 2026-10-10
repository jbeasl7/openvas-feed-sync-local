# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105534");
  script_version("2026-10-09T15:40:56+0000");
  script_tag(name:"last_modification", value:"2026-10-09 15:40:56 +0000 (Fri, 09 Oct 2026)");
  script_tag(name:"creation_date", value:"2016-02-10 12:03:48 +0100 (Wed, 10 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Application Policy Infrastructure Controller (APIC) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Application Policy Infrastructure
  Controller (APIC).");

  script_xref(name:"URL", value:"https://www.cisco.com/site/us/en/products/networking/cloud-networking/application-centric-infrastructure/application-policy-infrastructure-controller-apic/index.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if ("<title>APIC</title>" >< res && "APIC-Mode" >< res) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "cisco/apic/detected", value: TRUE);
  set_kb_item(name: "cisco/apic/http/detected", value: TRUE);

  cpe = "cpe:/a:cisco:application_policy_infrastructure_controller";

  url = "/insieme/stromboli/meta/Version.js";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: "versionString\s*:\s*'([0-9]+\.[^']+)'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    cpe += ":" + version;
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "Cisco Application Policy Infrastructure Controller (APIC) Detection (HTTP)");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Cisco Application Policy Infrastructure Controller (APIC)",
                                           version: version, install: location, cpe: cpe, concluded: vers[0],
                                           concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
