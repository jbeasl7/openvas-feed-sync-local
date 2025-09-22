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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801842");
  script_version("2022-06-08T09:12:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-06-08 09:12:49 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");

  script_cve_id("CVE-2011-0899");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal AES Encryption Module Information Disclosure Vulnerability (SA-CONTRIB-2011-005) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/http/detected");

  script_tag(name:"summary", value:"Drupal AES Encryption Module is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Due to a piece of code used for debugging mistakenly left in
  the release, the plain text password of the user who last logged in is written to a text file in
  the Drupal root directory. This file is remotely accessible.");

  script_tag(name:"impact", value:"An attacker with the knowledge of which user last logged in may
  access that user's account.");

  script_tag(name:"affected", value:"Drupal AES Encryption Module 7.x-1.4 is known to be affected.
  Older versions may be affected as well.");

  script_tag(name:"solution", value:"Update to Drupal AES Encryption Module 7.x-1.5 or later and
  remove the reported file from the remote system.");

  script_xref(name:"URL", value:"http://drupal.org/node/1048998");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46116");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65112");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/login_edit_dump.txt";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if (!res)
  exit(0);

# nb: Avoid false positives on systems which are always responding with a 200 status code...
if (!egrep(string:res, pattern:"^[Cc]ontent-[Tt]ype\s*:\s*text/(plain|txt)", icase:FALSE))
  exit(0);

if (res =~ "^HTTP/1\.[01] 200") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
