# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:sitracker:support_incident_tracker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100467");
  script_version("2022-05-25T10:52:06+0000");
  script_tag(name:"last_modification", value:"2022-05-25 10:52:06 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1596");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SiT! Support Incident Tracker < 3.51 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_support_incident_tracker_http_detect.nasl");
  script_mandatory_keys("sit/detected");

  script_tag(name:"summary", value:"Support Incident Tracker (SiT!) is prone to an authentication
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain unauthorized access
  to the affected application.");

  script_tag(name:"affected", value:"Support Incident Tracker (SiT!) prior to version 3.51.");

  script_tag(name:"solution", value:"Update to version 3.51 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37949");
  script_xref(name:"URL", value:"http://sitracker.org/wiki/ReleaseNotes351");

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

if (version_is_less(version: version, test_version: "3.51")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.51", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
