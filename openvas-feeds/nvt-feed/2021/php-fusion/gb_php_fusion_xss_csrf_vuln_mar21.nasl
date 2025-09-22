# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145877");
  script_version("2021-11-15T15:39:01+0000");
  script_tag(name:"last_modification", value:"2021-11-15 15:39:01 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 09:48:48 +0000 (Mon, 03 May 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-08 04:30:00 +0000 (Sat, 08 May 2021)");

  script_cve_id("CVE-2021-28280");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPFusion < 8.00.90 / 9.x < 9.10.00 XSS/CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"PHPFusion is prone to a cross-site scripting (XSS) and
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CSRF and XSS vulnerability in search.php allows remote attackers
  to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"PHPFusion version 9.03.110 and probably prior.");

  script_tag(name:"solution", value:"Update to version 8.00.90, 9.10.00 or later.

  Note: There are no clear changelog entries on the affected / fixed versions for the commits linked
  in the references so the releases after these commits have been made are currently assumed as the
  fixed versions.");

  script_xref(name:"URL", value:"https://anotepad.com/notes/2skndayt");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/08d6c2ea49bd06fcce32275252f5f25abe61965c");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/1c2b32321cf11ed1cd3ff835f8da0d172c849ce6");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/da9f89ae70219f357fba6fffd2dae1ec886d8a3b");
  script_xref(name:"URL", value:"https://github.com/PHPFusion/PHPFusion/commit/fda266c3bb35c650a8c4c51b6923abdfb66ef5cd");

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

if (version_is_less(version: version, test_version: "8.00.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.00.90", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^9\.[0-9]" && version_is_less(version: version, test_version: "9.10.00")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.10.00", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);