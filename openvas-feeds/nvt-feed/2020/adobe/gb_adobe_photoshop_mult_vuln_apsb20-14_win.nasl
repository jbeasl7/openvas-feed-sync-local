# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816819");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-3783", "CVE-2020-3784", "CVE-2020-3785", "CVE-2020-3786",
                "CVE-2020-3787", "CVE-2020-3788", "CVE-2020-3789", "CVE-2020-3790",
                "CVE-2020-3771", "CVE-2020-3777", "CVE-2020-3778", "CVE-2020-3781",
                "CVE-2020-3782", "CVE-2020-3791", "CVE-2020-3773", "CVE-2020-3779",
                "CVE-2020-3770", "CVE-2020-3772", "CVE-2020-3774", "CVE-2020-3775",
                "CVE-2020-3776", "CVE-2020-3780");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-26 18:43:00 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-19 16:28:03 +0000 (Thu, 19 Mar 2020)");
  script_name("Adobe Photoshop CC Multiple Vulnerabilities (APSB20-14) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A heap corruption error.

  - Multiple memory corruption errors.

  - Multiple out-of-bounds read and write errors.

  - Buffer errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information and execute arbitrary
  code in the context of the application.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2019 20.0.8 and earlier
  and Adobe Photoshop 2020 21.1 and earlier versions.");

  script_tag(name:"solution", value:"Update to Adobe Photoshop CC 2019 20.0.9
  or Photoshop CC 2020 21.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb20-14.html");

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Photoshop 2020 gets registered as Photoshop
cpe_list = make_list("cpe:/a:adobe:photoshop_cc2019", "cpe:/a:adobe:photoshop");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# nb: 21.1.1 == 21.1.1.121
if(vers =~ "^21\.") {
  if(version_is_less(version:vers, test_version:"21.1.1.121")) {
    fix = "21.1.1";
    installed_ver = "Adobe Photoshop CC 2020";
  }
}

else if(vers =~ "^20\.") {
  if(version_is_less(version:vers, test_version:"20.0.9")) {
    fix = "20.0.9";
    installed_ver = "Adobe Photoshop CC 2019";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);