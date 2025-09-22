# Copyright (C) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902530");
  script_version("2022-05-25T13:03:27+0000");
  script_tag(name:"last_modification", value:"2022-05-25 13:03:27 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-1563", "CVE-2011-1564");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ActivDesk < 3.0.1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ActivDesk is prone to multiple cross-site scripting (XSS) and
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Improper validation of user-supplied input passed to the 'keywords0', 'keywords1', 'keywords2'
  and 'keywords3' parameters in search.cgi, which allows attackers to execute arbitrary HTML and
  script code on the web server.

  - Improper validation of user-supplied input passed to the 'cid' parameter in kbcat.cgi and the
  'kid' parameter in kb.cgi, which allows attacker to manipulate SQL queries by injecting arbitrary
  SQL code.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"ActivDesk version 3.0 and prior.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45057/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46937");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17443/");
  script_xref(name:"URL", value:"http://itsecuritysolutions.org/2011-06-24-ActivDesk-3.0-multiple-security-vulnerabilities/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/adesk", "/support", "/hdesk", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: "/login.cgi");

  if (res !~ "^HTTP/1\.[01] 200" || "<title>Support</title>" >!< res)
    continue;

  url = dir + "/search.cgi?keywords0=<script>alert(document.cookie)</script>";

  if (http_vuln_check(port: port, url: url, check_header: TRUE,
                      pattern: "<script>alert\(document\.cookie\)</script>")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
