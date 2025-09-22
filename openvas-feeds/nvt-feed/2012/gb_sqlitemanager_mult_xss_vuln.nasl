# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:sqlitemanager:sqlitemanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802373");
  script_version("2022-01-18T12:40:16+0000");
  script_tag(name:"last_modification", value:"2022-01-18 12:40:16 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2012-01-06 13:17:25 +0530 (Fri, 06 Jan 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2012-5105");

  script_name("SQLiteManager <= 1.2.4 Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sqlitemanager/http/detected");

  script_tag(name:"summary", value:"SQLiteManager is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input
  via the 'dbsel' or 'nsextt' parameters to index.php or main.php script, which allows attacker to
  execute arbitrary HTML and script code on the user's browser session in the security context of
  an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"SQLiteManager version 1.2.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521126");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108393/sqlitemanager124-xss.txt");

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

url = dir + "/main.php?dbsel=</script><script>alert(document.cookie)</script>";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"</script><script>alert\(document\.cookie\)</script>")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
