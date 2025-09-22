# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105472");
  script_version("2025-06-27T15:42:32+0000");
  script_tag(name:"last_modification", value:"2025-06-27 15:42:32 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-12-01 15:47:56 +0100 (Tue, 01 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Identity Services Engine (ISE) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Identity Services Engine
  (ISE).");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/admin/login.jsp";

res = http_get_cache(port: port, item: url);

# nb: Newer versions check the agent and throw an error page (still with the title)
if ("<title>Identity Services Engine</title>" >< res &&
    (("Cisco Systems" >< res && 'productName="Identity Services Engine"' >< res) ||
     'href="/admin/error/error.css">' >< res)) {
  version = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "cisco/ise/detected", value: TRUE);
  set_kb_item(name: "cisco/ise/http/detected", value: TRUE);
  set_kb_item(name: "cisco/ise/http/port", value: port);

  set_kb_item(name: "cisco/ise/http/" + port + "/version", value: version);
  set_kb_item(name: "cisco/ise/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
