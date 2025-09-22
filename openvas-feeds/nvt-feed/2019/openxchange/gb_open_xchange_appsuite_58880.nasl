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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141831");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-01-07 15:21:56 +0700 (Mon, 07 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-31 23:52:00 +0000 (Thu, 31 Jan 2019)");

  script_cve_id("CVE-2018-12610", "CVE-2018-12611");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange (OX) App Suite Multiple Vulnerabilities (58880, 58051, 58029)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities:

  - Information Exposure (BugID: 58029)

  - Cross-Site Scripting (BugID: 58880, 58226)");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions 7.8.3 and 7.8.4.");

  script_tag(name:"solution", value:"Update to version 7.8.3-rev49, 7.8.4-rev34 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/Jan/10");

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

if (version =~ "^7\.8\.3" && version_is_less(version: version, test_version: "7.8.3.49")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.3.49", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version =~ "^7\.8\.4" && version_is_less(version: version, test_version: "7.8.4.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.4.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
