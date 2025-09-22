# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106106");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa EDS Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Moxa EDS devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_asp(port: port))
  exit(0);

url = "/auth/led_auth.asp";

res = http_get_cache(port: port, item: "/auth/led_auth.asp");

if (res && "MasterLEDName" >< res && res =~ "EDS\-[0-9]+") {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "moxa/eds/detected", value: TRUE);
  set_kb_item(name: "moxa/eds/http/detected", value: TRUE);
  set_kb_item(name: "moxa/eds/http/port", value: port);
  set_kb_item(name: "moxa/eds/http/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  # <PARAM name="ModelName" value="EDS-405A-T">
  mod = eregmatch(pattern: '"ModelName"\\s*value="(EDS-[^"]+)', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    concluded = "    Model concluded from: " + mod[0] + '\n';
  }

  # <PARAM name="FirmVersion" value="V2.4">
  vers = eregmatch(pattern: '"FirmVersion"\\s*value="V([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += "    Version concluded from: " + vers[0];
  }

  # <PARAM name="MACAddress" value="xx-xx-xx-xx-xx-xx">
  mac = eregmatch(pattern: '"MACAddress"\\s*value="([0-9A-F-]+)"', string: res);
  if (!isnull(mac[1])) {
    mac = str_replace(string: mac[1], find: "-", replace: ":");
    set_kb_item(name: "moxa/eds/http/" + port + "/mac", value: mac);
    register_host_detail(name: "MAC", value: mac, desc: "Moxa EDS Device Detection (HTTP)");
    replace_kb_item(name: "Host/mac_address", value: mac);
  }

  set_kb_item(name: "moxa/eds/http/" + port + "/model", value: model);
  set_kb_item(name: "moxa/eds/http/" + port + "/version", value: version);

  if (concluded)
    set_kb_item(name: "moxa/eds/http/" + port + "/concluded", value: chomp(concluded));
}

exit(0);
