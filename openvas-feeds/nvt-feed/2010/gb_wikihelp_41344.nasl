# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:wikiwebhelp:wiki_web_help";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100701");
  script_version("2021-11-19T06:55:06+0000");
  script_tag(name:"last_modification", value:"2021-11-19 06:55:06 +0000 (Fri, 19 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-4970");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Wiki Web Help <= 0.2.8 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wikiwebhelp_http_detect.nasl");
  script_mandatory_keys("wikiwebhelp/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Wiki Web Help is prone to an SQL injection (SQLi) vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Wiki Web Help 0.2.8 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"Updates are available, please see the references for more
  information.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/handlers/getpage.php?id=9999999+UNION+SELECT+1,0x53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7+FROM+user+LIMIT+1";

if (http_vuln_check(port: port, url: url,pattern: "SQL-Injection-Test")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
