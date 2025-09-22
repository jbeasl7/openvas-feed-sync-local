# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143219");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-12-05 03:43:36 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 18:15:00 +0000 (Thu, 28 May 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-7192", "CVE-2019-7193", "CVE-2019-7194", "CVE-2019-7195");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station Multiple Vulnerabilities (NAS-201911-25)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/PhotoStation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"QNAP Photo Station is prone to multiple vulnerabilities:

  - Improper access control vulnerability allows remote attackers to gain unauthorized access to the system (CVE-2019-7192)

  - Improper input validation vulnerability allows remote attackers to inject arbitrary code to the system (CVE-2019-7193)

  - External control of file name or path vulnerability allows remote attackers to access or modify system files
    (CVE-2019-7194, CVE-2019-7195)");

  script_tag(name:"affected", value:"QNAP Photo Station versions prior to 5.2.11, 5.4.9, 5.7.10 and 6.0.3.");

  script_tag(name:"solution", value:"Update to version 5.2.11, 5.4.9, 5.7.10, 6.0.3 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201911-25");

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

if (version_is_less(version: version, test_version: "5.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.4.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5", test_version2: "5.7.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.8", test_version2: "6.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
