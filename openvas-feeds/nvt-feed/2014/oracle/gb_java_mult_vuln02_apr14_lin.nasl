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
  script_oid("1.3.6.1.4.1.25623.1.0.108421");
  script_version("2022-09-19T10:11:35+0000");
  script_cve_id("CVE-2014-0432", "CVE-2014-0448", "CVE-2014-0454", "CVE-2014-0455",
                "CVE-2014-0459", "CVE-2014-2397", "CVE-2014-2402", "CVE-2014-2413",
                "CVE-2014-2422");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"creation_date", value:"2014-04-18 16:17:30 +0530 (Fri, 18 Apr 2014)");
  script_name("Oracle Java SE 7.x, 8.x Multiple Vulnerabilities (cpuapr2014) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Oracle/Java/JDK_or_JRE/Linux/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66898");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66899");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66910");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66917");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57997");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixJAVA");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate
  certain data, cause a DoS (Denial of Service) and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Oracle Java SE versions 7.x and 8.x.");

  script_tag(name:"solution", value:"Update to version 7 Update 55, 8 Update 5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.51") ||
   version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7 Update 55 (1.7.0.55) / 8 Update 5 (1.8.0.5)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
