# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803034");
  script_version("2023-02-24T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-02-24 10:20:04 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2012-09-27 16:41:55 +0530 (Thu, 27 Sep 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-0869", "CVE-2012-1293");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("F*EX (Frams's Fast File EXchange) < 20111129-2 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("fexsrv/banner");

  script_tag(name:"summary", value:"F*EX (Frams's Fast File EXchange) is prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The inputs passed via 'to', 'from' and 'id' parameter to 'fup'
  is not properly validated, which allows attackers to execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Frams' Fast File EXchange prior to version 20111129-2.");

  script_tag(name:"solution", value:"Update to version 20111129-2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47971");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52085");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48066");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q1/att-441/FEX_20100208.txt");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q1/att-441/FEX_20111129-2.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-02/0112.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8888);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: fexsrv" >!< banner)
  exit(0);

url = '/fup?id=38c66"><script>alert(document.cookie);</script>b08f61c45c6&to=%0d&from=%0d';

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document.cookie\);</script>",
                    extra_check: make_list("F*EX upload<", "F*EX server"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
