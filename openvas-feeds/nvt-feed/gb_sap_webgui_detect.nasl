# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141116");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-25 13:20:49 +0700 (Fri, 25 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP Web GUI Detection");

  script_tag(name:"summary", value:"Detection of SAP Web GUI.

SAP Web GUI offers the equivalent functions as a SAP GUI Client over HTTP/S accessible through a browser.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wiki.scn.sap.com/wiki/display/ATopics/SAP+GUI+Family");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = '/sap/bc/gui/sap/its/webgui';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "<title>Logon( - SAP Web Application Server)?</title>" && 'name="sap-system-login"' >< res) {
  set_kb_item(name: "sap_webgui/installed", value: TRUE);
  set_kb_item(name: "sap_webgui/port", value: port);

  report = "SAP Web GUI is enabled at the following URL:  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  log_message(port: port, data: report);
  exit(0);
}

exit(0);
