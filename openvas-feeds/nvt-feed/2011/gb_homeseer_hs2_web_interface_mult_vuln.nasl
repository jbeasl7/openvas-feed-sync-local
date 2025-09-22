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
  script_oid("1.3.6.1.4.1.25623.1.0.902648");
  script_version("2022-06-08T09:12:49+0000");
  script_tag(name:"last_modification", value:"2022-06-08 09:12:49 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2011-12-20 15:01:39 +0530 (Tue, 20 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-4835", "CVE-2011-4836", "CVE-2011-4837");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("HomeSeer HS2 Web Interface <= 2.5.0.20 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HomeSeer/banner");

  script_tag(name:"summary", value:"HomeSeer HS2 is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site and gain sensitive information via directory traversal attacks.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input
  passed via the URL, which allows attacker to conduct stored and reflective XSS by sending a
  crafted request with JavaScript to web interface and causing the JavaScript to be stored in the
  log viewer page.");

  script_tag(name:"affected", value:"HomeSeer HS2 version 2.5.0.20 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50978");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/796883");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71713");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port: port);

if (!banner || "Server: HomeSeer" >!< banner)
  exit(0);

url = "/stat<script>alert(document.cookie)</script>";

req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if (http_vuln_check(port:port, url:"/elog", pattern:"<script>alert\(document\.cookie\)</script>",
                    check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
