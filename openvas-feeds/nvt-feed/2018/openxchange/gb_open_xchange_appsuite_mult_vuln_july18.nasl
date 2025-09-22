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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141264");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-07-03 14:31:36 +0200 (Tue, 03 Jul 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-16 23:15:00 +0000 (Fri, 16 Aug 2019)");

  script_cve_id("CVE-2018-9997", "CVE-2018-9998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange (OX) App Suite Multiple Vulnerabilities (Jul 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities:

  - XXE vulnerability

  - Multiple XSS vulnerabilities (CVE-2018-9997)

  - Information Exposure (CVE-2018-9998)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 7.6.3-rev31, 7.8.2-rev31, 7.8.3-rev41, 7.8.4-rev28 or
later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Jul/12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if (version_is_less(version: version, test_version: "7.6.3.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.3.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.7", test_version2: "7.8.2.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.2.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.8.3", test_version2: "7.8.3.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.3.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.8.4", test_version2: "7.8.4.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.4.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
