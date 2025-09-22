# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143323");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-01-08 07:50:11 +0000 (Wed, 08 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ruckus Unleashed Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Ruckus Unleashed devices.");

  script_xref(name:"URL", value:"https://www.ruckuswireless.com/products/system-management-control/unleashed");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/admin/login.jsp";

res = http_get_cache(port: port, item: url);

if ("<title>Unleashed Login</title>" >< res && "ruckus_logo" >< res) {
  version = "unknown";
  model = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "ruckus/unleashed/detected", value: TRUE);
  set_kb_item(name: "ruckus/unleashed/http/detected", value: TRUE);

  url = "/upnp.jsp";

  res = http_get_cache(port: port, item: url);

  # <modelName>R310</modelName>
  mod = eregmatch(pattern: "<modelName>([^<]+)</modelName>", string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    set_kb_item(name: "ruckus/unleashed/model", value: model);
  }

  # <modelNumber>200.7.10.202</modelNumber>
  vers = eregmatch(pattern: "<modelNumber>([0-9.]+)</modelNumber>", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];

    if (url >!< conclUrl)
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:ruckuswireless:unleashed_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:ruckuswireless:unleashed_firmware";

  app_name = "Ruckus Unleashed Firmware";

  if (model != "unknown") {
    hw_name = "Ruckus Unleashed " + model;
    hw_cpe = "cpe:/h:ruckuswireless:" + tolower(model);
  } else {
    hw_name = "Ruckus Unleashed Unknown Model";
    hw_cpe = "cpe:/h:ruckuswireless:unleashed";
  }

  os_register_and_report(os: "Ruckus Unleashed Firmware", cpe: os_cpe, port: port,
                         desc: "Ruckus Unleashed Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: os_cpe, location: location, port: port, service: "www");
  register_product(cpe: hw_cpe, location: location, port: port, service: "www");

  report = build_detection_report(app: app_name, version: version, install: location, cpe: os_cpe,
                                  concluded: vers[0], concludedUrl: conclUrl);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe,
                                   concluded: mod[0]);

  log_message(port: port, data: report);
  exit(0);
}

exit(0);
