# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105348");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-09-08 16:28:06 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Cisco Integrated Management Controller (IMC) Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_redfish_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Integrated Management Controller
  (IMC).");

  script_xref(name:"URL", value:"https://www.cisco.com/site/us/en/products/computing/servers-unified-computing-systems/ucs-integrated-management-controller-cimc/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if ("<title>Cisco Integrated Management Controller Login</title>" >!< res &&
    "<title>Cisco Integrated Management Controller</title>" >!< res )
  exit(0);

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "cisco/imc/detected", value: TRUE);
set_kb_item(name: "cisco/imc/http/detected", value: TRUE);

url = "/public/cimc.esp";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

vers = eregmatch(pattern: 'var fwVersion = "([^"]+)";', icase: TRUE, string: res);
if (isnull(vers[1])) {
  url = "/esp/cimc.esp";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: 'var\\s+fwVersion\\s*=\\s*"([^"]+)";', icase: TRUE, string: res);
}

if (!isnull(vers[1])) {
  version = chomp(vers[1]);
  concluded = vers[0];
  conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
} else {
  if (vers = get_kb_item("redfish/api/" + port + "/cimc_fw_version")) {
    version = vers;
    concluded = vers;
    if (redfish_url = get_kb_item("redfish/api/" + port + "/cimc_concluded_url")) {
      conclUrl += '\n  ' + redfish_url;
    }
  }
}

if (version == "unknown")
  extra = "  Note: For extended version extraction please provide credentials for the Redfish API in " +
          "'Redfish API Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.149998)";

cpe = build_cpe(value: version, exp: "^([0-9A-Za-z\(\).]+)",
                base: "cpe:/a:cisco:integrated_management_controller:");
if (!cpe)
  cpe = "cpe:/a:cisco:integrated_management_controller";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app:"Cisco Integrated Management Controller (IMC)", version: version,
                                         install: location, cpe: cpe, concluded: concluded,
                                         concludedUrl: conclUrl, extra: extra),
            port: port);
exit(0);
