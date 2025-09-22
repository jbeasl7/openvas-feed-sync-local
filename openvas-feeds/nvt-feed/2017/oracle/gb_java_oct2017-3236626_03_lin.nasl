# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108380");
  script_version("2022-06-24T09:38:38+0000");
  script_cve_id("CVE-2016-9841");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-24 09:38:38 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-22 17:16:00 +0000 (Wed, 22 Jun 2022)");
  script_tag(name:"creation_date", value:"2017-10-18 13:04:32 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle Java SE Security Update (cpuoct2017 - 03) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to a flaw in Util (zlib) component of
  the application.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will allow
  attackers to partially modify data by leveraging improper pointer arithmetic within the
  application.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0.161 and earlier, 1.7.0.151 and
  earlier, 1.8.0.144 and earlier.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2017.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95131");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk", "cpe:/a:sun:jre", "cpe:/a:sun:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]\.") {
  if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.161") ||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.151") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.144")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
