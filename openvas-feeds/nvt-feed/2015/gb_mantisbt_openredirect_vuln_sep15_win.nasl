# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805972");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2015-1042");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-09-07 12:56:25 +0530 (Mon, 07 Sep 2015)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MantisBT 1.2.x < 1.2.19 Open Redirect Vulnerability - Windows");

  script_tag(name:"summary", value:"MantisBT is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to use of an incorrect regular
  expression within string_sanitize_url function in core/string_api.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing.");

  script_tag(name:"affected", value:"MantisBT versions 1.2.0a3 through 1.2.18.");

  script_tag(name:"solution", value:"Update to version 1.2.19 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/130142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71988");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/110");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/01/10/5");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");

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

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "1.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
