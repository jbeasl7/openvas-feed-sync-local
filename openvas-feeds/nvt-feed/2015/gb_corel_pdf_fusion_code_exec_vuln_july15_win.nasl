# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:corel:pdf_fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805674");
  script_version("2022-10-11T10:12:36+0000");
  script_cve_id("CVE-2014-8396");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-10-11 10:12:36 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2015-07-07 16:52:25 +0530 (Tue, 07 Jul 2015)");
  script_name("Corel PDF Fusion <= 1.14 Arbitrary Code Execution Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_corel_pdf_fusion_smb_login_detect.nasl");
  script_mandatory_keys("corel/pdf_fusion/detected");

  script_tag(name:"summary", value:"Corel PDF Fusion is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the way it loads dynamic-link libraries (DLL)
  such as the 'wintab32.dll' or 'quserex.dll' libraries. The program uses a fixed path to look for
  specific files or libraries. This path includes directories that may not be trusted or under user
  control.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to inject
  custom code.");

  script_tag(name:"affected", value:"Corel PDF Fusion through version 1.14.");

  script_tag(name:"solution", value:"As a workaround users should avoid opening untrusted files
  whose extensions are associated with Corel software and contain any of the DLL files.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/corel-software-dll-hijacking");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72007");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"1.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
