# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:prestashop:prestashop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112427");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-11-13 14:32:22 +0100 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 18:33:00 +0000 (Wed, 12 Dec 2018)");

  script_cve_id("CVE-2018-19126");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PrestaShop 1.7.4.x < 1.7.4.4, 1.6.1.x < 1.6.1.23 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_http_detect.nasl");
  script_mandatory_keys("prestashop/detected");

  script_tag(name:"summary", value:"PrestaShop is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue exists on the file manager integrated in the text
  editor component in the Back Office. By exploiting a combination of security vulnerabilities, an
  authenticated user in the Back Office could upload a malicious file that would then allow him or
  her to execute arbitrary code on the server.");

  script_tag(name:"affected", value:"PrestaShop 1.6.1.x before 1.6.1.23 and 1.7.4.x before 1.7.4.4.");

  script_tag(name:"solution", value:"Update to version 1.6.1.23, 1.7.4.4 or later.");

  script_xref(name:"URL", value:"http://build.prestashop.com/news/prestashop-1-7-4-4-1-6-1-23-maintenance-releases/");
  script_xref(name:"URL", value:"https://github.com/PrestaShop/PrestaShop/pull/11286");
  script_xref(name:"URL", value:"https://github.com/PrestaShop/PrestaShop/pull/11285");

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

if (version_in_range(version: version, test_version: "1.7.4.0", test_version2: "1.7.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.6.1.0", test_version2: "1.6.1.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.1.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
