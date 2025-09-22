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

CPE = "cpe:/a:sitracker:support_incident_tracker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103349");
  script_version("2022-05-25T10:52:06+0000");
  script_tag(name:"last_modification", value:"2022-05-25 10:52:06 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2011-11-30 11:40:15 +0100 (Wed, 30 Nov 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Support Incident Tracker 3.45 - 3.65 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_support_incident_tracker_http_detect.nasl");
  script_mandatory_keys("sit/detected");

  script_tag(name:"summary", value:"Support Incident Tracker is prone to a remote code execution
  (RCE) vulnerability because the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary
  PHP code within the context of the affected application.");

  script_tag(name:"affected", value:"Support Incident Tracker version 3.45 through 3.65.");

  script_tag(name:"solution", value:"See the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520577");

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

if (version_in_range(version: version, test_version: "3.45", test_version2: "3.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
