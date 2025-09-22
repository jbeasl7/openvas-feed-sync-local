# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142010");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2019-02-20 16:34:48 +0700 (Wed, 20 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation PowerMonitor Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Rockwell Automation PowerMonitor
  devices.");

  script_xref(name:"URL", value:"https://ab.rockwellautomation.com/Energy-Monitoring/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/overview.shtm";

res = http_get_cache(port: port, item: url);

if ("Rockwell Automation" >!< res || "<title>PowerMonitor" >!< res) {
  url = "/body.htm";

  res = http_get_cache(port: port, item: url);

  if (">Powermonitor" >!< res || ">Catalog Number:<" >!< res)
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

mod = eregmatch(pattern: ">Powermonitor ([0-9]+)", string: res);
if (!isnull(mod[1])) {
  model = mod[1];
} else {
  url = "/";

  res2 = http_get_cache(port: port, item: url);

  mod = eregmatch(pattern: "<title>Powermonitor ([0-9]+)", string: res2, icase: TRUE);
  if (!isnull(mod[1])) {
    model = mod[1];
    conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
}

# "Firmware_Revision">Revision 4.10
vers = eregmatch(pattern: '"Firmware_Revision">Revision ([0-9.]+)', string: res);
if (!isnull(vers[1]))
  version = vers[1];
else {
  # <td>Operating System Version</td>
  # <td><div id = "OS">411</div></td>
  vers = eregmatch(pattern: '"OS">([0-9]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
  } else {
    # <td><b>Operating System Version:</b></td><td>330</td></tr><tr>
    vers = eregmatch(pattern: ">Operating System Version:[^>]+>[^>]+>[^>]+>([0-9]+)<", string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }
}

# <td><div id = "Catalog">1408-EM3A-ENT B</div></td>
prod = eregmatch(pattern: '"Catalog">([^<]+)<', string: res);
if (isnull(prod[1]))
  # <td><b>Catalog Number:</b></td><td>1408-EM3A-ENTA</td></tr><tr>
  prod = eregmatch(pattern: "Catalog Number:[^>]+>[^>]+>[^>]+>([^<]+)<", string: res);

if (!isnull(prod[1])) {
  set_kb_item(name: "rockwellautomation/powermonitor/catalog_number", value: prod[1]);
  extra = "Catalog Number: " + prod[1] + '\n';
}

# "Ethernet_Address">F4:54:33:54:C0:E1
mac = eregmatch(pattern: '"Ethernet_Address">([A-F0-9:]{17})', string: res);
if (!isnull(mac[1])) {
  register_host_detail(name: "MAC", value: mac[1], desc: "gb_rockwell_powermonitor_http_detect.nasl");
  replace_kb_item(name: "Host/mac_address", value: mac[1]);
  extra += "Mac Address:   " + mac[1] + '\n';
}

set_kb_item(name: "rockwellautomation/powermonitor/detected", value: TRUE);
set_kb_item(name: "rockwellautomation/powermonitor/http/detected", value: TRUE);

if (model) {
  app_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                      base: "cpe:/a:rockwellautomation:powermonitor" + model + ":");
  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                     base: "cpe:/o:rockwellautomation:powermonitor" + model + ":");
  hw_cpe = "cpe:/h:rockwellautomation:powermeter" + model;
} else {
  app_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                      base: "cpe:/a:rockwellautomation:powermonitor:");
  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                     base: "cpe:/o:rockwellautomation:powermonitor:");
  hw_cpe = "cpe:/h:rockwellautomation:powermeter";
}

os_register_and_report(os: "Rockwell Automation PowerMonitor Firmware", cpe: os_cpe,
                       desc: "Rockwell Automation PowerMonitor Detection (HTTP)", runs_key: "unixoide");

register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
register_product(cpe: os_cpe, location: "/", port: port, service: "www");
register_product(cpe: app_cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "Rockwell Automation PowerMonitor " + model, version: version,
                                         install: "/", cpe: app_cpe, concluded: vers[0],
                                         concludedUrl: conclUrl, extra: chomp(extra)),
            port: port);

exit(0);
