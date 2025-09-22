# SPDX-FileCopyrightText: 2003 Sullo
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netscape:server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11220");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Netscape /.perf accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Sullo");
  script_family("Web Servers");
  script_dependencies("gb_netscape_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netscape/server/detected");

  script_tag(name:"solution", value:"If you don't use this feature, server monitoring should be
  disabled in the magnus.conf file or web server admin.");

  script_tag(name:"summary", value:"Requesting the URI /.perf gives information about
  the currently running Netscape/iPlanet web server.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/.perf";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("ListenSocket" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
