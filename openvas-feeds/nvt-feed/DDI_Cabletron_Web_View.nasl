# SPDX-FileCopyrightText: 2005 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10962");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cabletron Web View Administrative Access (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Digital Defense Inc.");
  script_family("Privilege escalation");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Depending on the location of the switch, it might
  be advisable to restrict access to the web server by IP address or disable the web
  server completely.");

  script_tag(name:"summary", value:"This host is a Cabletron switch and is running
  Cabletron WebView. This web software provides a graphical, real-time representation of
  the front panel on the switch. This graphic, along with additionally defined areas of the
  browser interface, allow you to interactively configure the switch, monitor its status, and
  view statistical information. An attacker can use this to gain information about this host.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/chassis/config/GeneralChassisConfig.html";
res = http_get_cache(item:url, port:port);

if("Chassis Configuration" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
