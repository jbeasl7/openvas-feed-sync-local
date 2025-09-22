# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:oracle:e-business_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811016");
  script_version("2023-02-16T10:19:47+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:19:47 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2017-04-27 11:25:39 +0530 (Thu, 27 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-3549");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle E-Business Suite 'IESFOOTPRINT' SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_ebusiness_suite_http_detect.nasl");
  script_mandatory_keys("oracle/ebs/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Oracle E-Business Suite is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks the
  response.");

  script_tag(name:"insight", value:"The vulnerability exists due to some unspecified error within
  the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  sensitive data, modify or delete data from database.");

  script_tag(name:"affected", value:"Oracle E-Business Suite versions 12.1.1, 12.1.2, 12.1.3,
  12.2.3, 12.2.4, 12.2.5 and 12.2.6.");

  script_tag(name:"solution", value:"Apply the patch from the referenced vendor advisory.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97748");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41926");
  script_xref(name:"URL", value:"https://erpscan.io/advisories/erpscan-17-021-sql-injection-e-business-suite-iesfootprint");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/OA_HTML/AppsLocalLogin.jsp";

req = http_get(port:port, item:url);
res = http_keepalive_send_recv(port:port, data:req);

redirect = eregmatch(pattern:"Location: .*(/OA.*)</A></BODY></HTML>", string:res);
if(redirect[1]) {
  req = http_get(item:dir + redirect[1], port:port);
  res = http_keepalive_send_recv(port:port, data:req);
}

if(res && "Set-Cookie:" >< res) {
  cookie1 = eregmatch(pattern:"Set-Cookie: (JSESSIONID[^;]+)", string:res);
  if(!cookie1[1])
    exit(0);

  cookie2 = eregmatch(pattern:"Set-Cookie: ([^J;]+)", string:res);
  if(!cookie2[1])
    exit(0);

  cookie = cookie1[1] + "; " + cookie2[1];

  if(res && "title>Login</title" >< res && 'content="Oracle UIX' >< res) {
    url = dir + "/OA_HTML/iesfootprint.jsp?showgraph=%3C%3Etrue&dscriptId=%3C%3ESQL%20Injection%20Test";

    if(http_vuln_check(port:port, url:url, pattern:">SQL Injection Test",
                       check_header:TRUE, cookie:cookie,
                       extra_check:make_list(">Sign Out<", ">Oracle Applications<"))) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(0);
