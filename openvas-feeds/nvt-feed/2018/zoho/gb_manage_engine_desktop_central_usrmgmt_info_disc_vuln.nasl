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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812522");
  script_version("2023-01-19T10:10:48+0000");
  script_cve_id("CVE-2017-16924");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-02-23 16:17:29 +0530 (Fri, 23 Feb 2018)");
  script_name("ManageEngine Desktop Central <= 10.0.137 'usermgmt.xml' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"ManageEngine Desktop Central is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue exists in an unknown function of the file
  '/client-data//collections/##/usermgmt.xml'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to download
  unencrypted XML files containing all data for configuration policies.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central/MSP version 10.0.137 and prior.");

  script_tag(name:"solution", value:"Update to version 10.0.157 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.manageengine.com/desktop-management-msp/password-encryption-policy-violation.html");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_http_detect.nasl");
  script_mandatory_keys("manageengine/desktop_central/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"10.0.137")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.0.157", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
