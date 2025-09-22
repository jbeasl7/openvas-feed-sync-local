# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:enalean:tuleap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106379");
  script_version("2021-10-19T05:42:00+0000");
  script_tag(name:"last_modification", value:"2021-10-19 05:42:00 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-07 12:46:37 +0700 (Mon, 07 Nov 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tuleap < 8.19.99.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tuleap_http_detect.nasl");
  script_mandatory_keys("tuleap/detected");

  script_tag(name:"summary", value:"Tuleap is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tuleap is prone to multiple vulnerabilities:

  - SQL injection in /widgets/updatelayout.php in the 'layout_id' parameter.

  - Reflected XSS in /svn/index.php.

  - Reflected XSS in /admin/grouplist.php.");

  script_tag(name:"impact", value:"An authenticated attacker may inject SQL commands,
  unauthenticated attackers may inject web script or HTML and steal sensitive data and
  credentials.");

  script_tag(name:"affected", value:"Tuleap before version 8.19.99.5.");

  script_tag(name:"solution", value:"Update to version 8.19.99.5 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40556");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.19.99.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.19.99.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);