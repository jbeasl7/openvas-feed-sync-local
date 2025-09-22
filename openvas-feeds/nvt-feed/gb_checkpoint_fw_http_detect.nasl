# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140453");
  script_version("2024-06-04T05:05:28+0000");
  script_tag(name:"last_modification", value:"2024-06-04 05:05:28 +0000 (Tue, 04 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-10-26 09:29:26 +0700 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Check Point Firewall Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Check Point Firewall.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

# <meta name="others" content="WEBUI LOGIN PAGE"  /><TITLE>Gaia</TITLE>
# <meta name="others" content="WEBUI LOGIN PAGE"  /><TITLE>GAiA</TITLE>
#
if (egrep(pattern: "<TITLE>Gaia</TITLE>", string: res, icase: TRUE) && "/cgi-bin/home.tcl" >< res) {
  version = "unknown";
  build = "unknown";

  set_kb_item(name: "checkpoint/firewall/detected", value: TRUE);
  set_kb_item(name: "checkpoint/firewall/http/detected", value: TRUE);
  set_kb_item(name: "checkpoint/firewall/http/port", value: port);
  set_kb_item(name: "checkpoint/firewall/http/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  # var version='R77.30'
  # var version='R80.10'
  # ;var version='R81.10';var formAction="/cgi-bin/home.tcl";
  vers = eregmatch(pattern: "var version='([0-9R.]+)'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "checkpoint/firewall/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: "checkpoint/firewall/http/" + port + "/version", value: version);
  set_kb_item(name: "checkpoint/firewall/http/" + port + "/build", value: build);
}

exit(0);
