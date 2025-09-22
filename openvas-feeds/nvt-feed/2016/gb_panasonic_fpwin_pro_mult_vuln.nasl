# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.809029");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-4496", "CVE-2016-4497", "CVE-2016-4498", "CVE-2016-4499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:18:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-09-01 13:08:12 +0530 (Thu, 01 Sep 2016)");
  script_name("Panasonic FPWIN Pro Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_panasonic_fpwin_pro_detect_win.nasl");
  script_mandatory_keys("panasonic/control_fpwin_pro/detected");

  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-16-332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90523");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90522");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-16-334");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-16-335");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-16-330");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-131-01");

  script_tag(name:"summary", value:"Panasonic FPWIN Pro is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A heap-based buffer overflow error.

  - An uninitialized pointer access error.

  - An out-of-bounds write error.

  - A type confusion error.");

  script_tag(name:"impact", value:"Successful exploitation allows local
  users to cause a denial of service or possibly have other unspecified impact.");

  script_tag(name:"affected", value:"Panasonic FPWIN Pro 5.x through 7.x
  before 7.130.");

  script_tag(name:"solution", value:"Update to Panasonic FPWIN Pro version 7.1.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

CPE = "cpe:/a:panasonic:control_fpwin_pro";

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"5.0", test_version2:"7.1.2.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.1.3.0", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
