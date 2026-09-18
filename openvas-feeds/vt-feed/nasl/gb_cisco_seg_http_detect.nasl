# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105314");
  script_version("2026-09-17T05:45:41+0000");
  script_tag(name:"last_modification", value:"2026-09-17 05:45:41 +0000 (Thu, 17 Sep 2026)");
  script_tag(name:"creation_date", value:"2015-07-06 11:43:00 +0200 (Mon, 06 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Secure Email Gateway (SEG) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Secure Email Gateway (SEG)
  (formerly Cisco Email Security Appliance (ESA)).");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/login?redirects=20";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "<title>\s*Cisco\s*Email Security (Virtual )?Appliance" &&
    (res !~ "<title>\s*Cisco\s+Gateway( Virtual)?" || "yui_webui" >!< res))
  exit(0);

version = "unknown";
model = "unknown";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "cisco/seg/detected", value: TRUE);
set_kb_item(name: "cisco/seg/http/detected", value: TRUE);
set_kb_item(name: "cisco/seg/http/port", value: port);

vers = eregmatch(pattern: 'text_login_version">Version: ([^<]+)</p>', string: res);
if (isnull(vers[1]))
  vers = eregmatch(pattern: "/scfw/1y-([0-9.-]+)/yui/", string: res);

if (!isnull(vers[1])) {
  version = vers[1];
  concluded = "    Version: " + vers[0] + '\n';
}

mod = eregmatch(pattern: 'text_login_model">(Cisco )?\\s*Gateway\\s+(Virtual\\s*)?([^<]+)</p>', string: res);
if (!isnull(mod[3])) {
  model = chomp(mod[3]);
  model = ereg_replace(pattern: '\n', string: model, replace: "");
  concluded += "    Model: " + mod[0];
}

set_kb_item(name: "cisco/seg/http/" + port + "/version", value: version);
set_kb_item(name: "cisco/seg/http/" + port + "/model", value: model);
set_kb_item(name: "cisco/seg/http/" + port + "/concludedUrl", value: conclUrl);
if (concluded)
  set_kb_item(name: "cisco/seg/http/" + port + "/concluded", value: chomp(concluded));

exit(0);
