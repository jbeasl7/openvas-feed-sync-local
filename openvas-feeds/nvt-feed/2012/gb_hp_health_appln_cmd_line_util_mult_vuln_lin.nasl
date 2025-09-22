# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:system_health_application_and_command_line_utilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802776");
  script_version("2022-05-12T06:39:51+0000");
  script_cve_id("CVE-2012-2000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-12 06:39:51 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2012-05-11 10:46:35 +0530 (Fri, 11 May 2012)");
  script_name("HP System Health Application and Command Line Utilities < 9.0.0 Multiple Vulnerabilities - Linux");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hp_health_appln_cmd_line_utilities_ssh_login_detect.nasl");
  script_mandatory_keys("hp/system_health_and_clu/ssh-login/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49051/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53336");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/49051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522549");

  script_tag(name:"summary", value:"HP System Health Application and Command Line Utilities are
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to unspecified errors in the application.

  NOTE: Further information is not available.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
  arbitrary code via unknown vectors.");

  script_tag(name:"affected", value:"HP System Health Application and Command Line Utilities
  versions prior to 9.0.0.");

  script_tag(name:"solution", value:"Update to version 9.0.0 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"9.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.0.0", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
