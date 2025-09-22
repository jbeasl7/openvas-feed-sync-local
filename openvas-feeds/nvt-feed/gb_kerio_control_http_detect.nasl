# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140067");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-11-17 12:32:06 +0100 (Thu, 17 Nov 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kerio Control Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Kerio Control.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 4081);

url = "/login";

res = http_get_cache(port: port, item: url);

if (egrep(pattern: "[Ss]erver\s*:\s*Kerio Control Embedded Web Server", string: res, icase: FALSE) ||
    ("var kerio" >< res && "kerio.engine" >< res)) {
  version = "unknown";
  build = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "kerio/control/detected", value: TRUE);
  set_kb_item(name: "kerio/control/http/detected", value: TRUE);
  set_kb_item(name: "kerio/control/http/port", value: port);

  url = "/weblib/int/webAssist/webAssist.js";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # this.k_version = '9.4.5-8573';
  vers = eregmatch(pattern: "this.k_version\s*=\s*'([0-9.]+)\-([0-9]+)'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "kerio/control/http/" + port + "/concluded", value: vers[0]);
    conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    if (!isnull(vers[2]))
      build = vers[2];
  }

  set_kb_item(name: "kerio/control/http/" + port + "/version", value: version);
  set_kb_item(name: "kerio/control/http/" + port + "/build", value: build);
  set_kb_item(name: "kerio/control/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
