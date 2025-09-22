# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140948");
  script_version("2024-09-24T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-09-24 05:05:44 +0000 (Tue, 24 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-04-05 10:54:07 +0700 (Thu, 05 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trellix IPS Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Trellix IPS Manager (formerly McAfee
  Network Security Manager (NSM)).");

  script_xref(name:"URL", value:"https://www.trellix.com/products/intrusion-prevention-system/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/intruvert/jsp/module/Login.jsp";

res = http_get_cache(port: port, item: url);

if (("Trellix IPS Manager" >< res || "Network Security Manager" >< res) &&
    'alt="Dashboard" title="Dashboard">' >< res) {
  version = "unknown";
  location = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(pattern: "/intruvert/([0-9.]+)/", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "trellix/ips_manager/detected", value: TRUE);
  set_kb_item(name: "trellix/ips_manager/http/detected", value: TRUE);

  cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:trellix:intrusion_prevention_system_manager:");
  cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:network_security_manager:");
  if (!cpe1) {
    cpe1 = "cpe:/a:trellix:intrusion_prevention_system_manager";
    cpe2 = "cpe:/a:mcafee:network_security_manager";
  }

  register_product(cpe: cpe1, location: location, port: port, service: "www");
  register_product(cpe: cpe2, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Trellix IPS Manager", version: version, install: location,
                                           cpe: cpe1, concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
