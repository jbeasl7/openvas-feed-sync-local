# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150650");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-05-31 08:42:17 +0000 (Mon, 31 May 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 18:47:00 +0000 (Thu, 06 Oct 2022)");

  # nb: From the vendor advisory:
  # The fix for CVE-2019-7317 also addresses CVE-2019-6129.
  script_cve_id("CVE-2019-7317", "CVE-2019-2821", "CVE-2019-2769", "CVE-2019-2762", "CVE-2019-2745",
                "CVE-2019-2816", "CVE-2019-2842", "CVE-2019-2786", "CVE-2019-2818", "CVE-2019-2766",
                "CVE-2019-6129");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK Multiple Vulnerabilities (Jul 2019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the
  vulnerabilities.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 12.0.1, 11.0.3, 8u212 (1.8.0.212),
  7u221 (1.7.0.221) and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://openjdk.java.net/groups/vulnerability/advisories/2019-07-16");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2019-July/000000.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( vers =~ "^12" && version_is_less_equal( version:vers, test_version:"12.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( vers =~ "^11" && version_is_less_equal( version:vers, test_version:"11.0.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( vers =~ "^1\.8" && version_is_less_equal( version:vers, test_version:"1.8.0.212" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( vers =~ "^1\.7" && version_is_less_equal( version:vers, test_version:"1.7.0.221" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );