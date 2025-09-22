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

CPE = "cpe:/a:hp:snmp_agents_for_linux";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802775");
  script_version("2022-05-12T06:39:51+0000");
  script_cve_id("CVE-2012-2001", "CVE-2012-2002");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-12 06:39:51 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2012-05-10 17:50:17 +0530 (Thu, 10 May 2012)");
  script_name("HP SNMP Agents < 9.0.0 Open Redirect and XSS Vulnerabilities - Linux");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hp_snmp_agents_ssh_login_detect.nasl");
  script_mandatory_keys("hp/snmp_agents/ssh-login/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48978/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53340");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/48978");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522546");

  script_tag(name:"summary", value:"HP SNMP Agents are prone to open redirect and cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to input is not properly sanitised before
  being returned to the user and being used to redirect users.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute script
  code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"HP SNMP Agents versions prior to 9.0.0.");

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
