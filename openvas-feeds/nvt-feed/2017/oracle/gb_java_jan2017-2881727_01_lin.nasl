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
  script_oid("1.3.6.1.4.1.25623.1.0.108372");
  script_version("2022-05-19T11:50:09+0000");
  script_cve_id("CVE-2016-2183", "CVE-2017-3231", "CVE-2017-3261", "CVE-2016-5548",
                "CVE-2017-3253", "CVE-2017-3272", "CVE-2017-3252", "CVE-2017-3259",
                "CVE-2016-5552", "CVE-2016-5546", "CVE-2017-3241");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-19 11:50:09 +0000 (Thu, 19 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-01-18 18:42:10 +0530 (Wed, 18 Jan 2017)");
  script_name("Oracle Java SE Security Updates (jan2017-2881727) 01 - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'Libraries', 'RMI', '2D', 'JAAS', 'Networking' and
  'Deployment' sub-components.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow attackers to cause some unspecified impacts.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0.131 and
  earlier, 1.7.0.121 and earlier, 1.8.0.112 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95563");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95566");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95559");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95498");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95533");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95509");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95488");
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
  if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.131") ||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.121") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.112")) {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}

exit(99);
