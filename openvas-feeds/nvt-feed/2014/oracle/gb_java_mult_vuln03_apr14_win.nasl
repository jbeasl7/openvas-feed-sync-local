# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804546");
  script_version("2022-09-19T10:11:35+0000");
  script_cve_id("CVE-2014-0449", "CVE-2014-0452", "CVE-2014-0456", "CVE-2014-0458",
                "CVE-2014-0461", "CVE-2014-2403", "CVE-2014-2409", "CVE-2014-2414",
                "CVE-2014-2420", "CVE-2014-2423", "CVE-2014-2428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"creation_date", value:"2014-04-18 16:32:50 +0530 (Fri, 18 Apr 2014)");
  script_name("Oracle Java SE 6.x, 7.x, 8.x Multiple Vulnerabilities (cpuapr2014) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66891");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66915");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66919");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57997");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixJAVA");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate
  certain data, cause a DoS (Denial of Service) and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Oracle Java SE versions 6.x, 7.x and 8.x.");

  script_tag(name:"solution", value:"Update to version 7 Update 55, 8 Update 5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.71") ||
   version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.51") ||
   version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7 Update 55 (1.7.0.55) / 8 Update 5 (1.8.0.5)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
