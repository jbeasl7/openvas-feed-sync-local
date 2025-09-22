# SPDX-FileCopyrightText: 2003 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11977");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1785");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Invision Power Board Calendar SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"remote_vul");

  script_copyright("Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"The remote host is running Invision Power Board - a CGI suite designed to
  set up a bulletin board system on the remote web server.

  A vulnerability has been discovered in the sources/calendar.php file that allows unauthorized users to inject SQL
  commands.");

  script_tag(name:"insight", value:"An attacker may use this flaw to gain the control of the remote database");

  script_xref(name:"URL", value:"http://www.invisionboard.com/download/index.php?act=dl&s=1&id=12&p=1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9232");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?act=calendar&y=2004&m=1'";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

find = string("checkdate() expects parameter");
find2 = string("mySQL query error");

if (find >< res  || find2 >< res ){
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
