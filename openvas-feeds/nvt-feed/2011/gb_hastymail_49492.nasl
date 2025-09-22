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

CPE = "cpe:/a:hastymail:hastymail2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103244");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-08 12:04:18 +0200 (Thu, 08 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hastymail2 < 1.1 RC1 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hastymail2_detect.nasl");
  script_mandatory_keys("hastymail2/detected");

  script_tag(name:"summary", value:"Hastymail2 is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to launch other
  attacks.");

  script_tag(name:"affected", value:"Hastymail2 prior to version 1.1 RC1.");

  script_tag(name:"solution", value:"Update to version 1.1 RC1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49492");
  script_xref(name:"URL", value:"http://hastymail.svn.sourceforge.net/viewvc/hastymail/trunk/hastymail2/CHANGES?revision=1983");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.1rc1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1 RC1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
