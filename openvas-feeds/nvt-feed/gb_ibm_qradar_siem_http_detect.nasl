# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141118");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2018-05-29 10:38:49 +0700 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM QRadar SIEM Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of IBM QRadar SIEM.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/console/logon.jsp";

res = http_get_cache(port: port, item: url);

if ((">IBM QRadar" >< res || "<title>Login Page</title>" >< res) &&
    ("Login To QRadar" >< res || "Your local QRadar password has expired" >< res)) {
  version = "unknown";

  set_kb_item(name: "ibm/qradar/siem/detected", value: TRUE);
  set_kb_item(name: "ibm/qradar/siem/http/detected", value: TRUE);
  set_kb_item(name: "ibm/qradar/siem/http/port", value: port);
  set_kb_item(name: "ibm/qradar/siem/http/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  set_kb_item(name: "ibm/qradar/siem/http/" + port + "/version", value: version);

  exit(0);
}

exit(0);
