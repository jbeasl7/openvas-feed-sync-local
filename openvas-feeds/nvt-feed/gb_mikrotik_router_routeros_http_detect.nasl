# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113071");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-12-14 13:25:48 +0100 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik RouterOS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of MikroTik RouterOS.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

# <div class="top">mikrotik routeros 6.19 configuration page</div>
# <h1>RouterOS v6.34.6</h1>
if ((">RouterOS router configuration page<" >< res && "mikrotik<" >< res && ">Login<" >< res) ||
    (">mikrotik routeros" >< res && "configuration page</div>" >< res) ||
    ("<title>RouterOS</title>" >< res && res =~ ">Login:?<")) {

  version = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "mikrotik/routeros/detected", value: TRUE);
  set_kb_item(name: "mikrotik/routeros/http/detected", value: TRUE);
  set_kb_item(name: "mikrotik/routeros/http/port", value: port);

  vers = eregmatch(pattern:">RouterOS v([A-Za-z0-9.]+)<", string: res);
  if (isnull(vers[1]))
    vers = eregmatch(pattern: ">mikrotik routeros ([A-Za-z0-9.]+) configuration page<", string: res);

  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "mikrotik/routeros/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: "mikrotik/routeros/http/" + port + "/version", value: version);
  set_kb_item(name: "mikrotik/routeros/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
