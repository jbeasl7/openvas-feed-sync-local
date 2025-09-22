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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:lightroom_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817871");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-24447");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-11 18:25:00 +0000 (Fri, 11 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-10 11:06:38 +0530 (Thu, 10 Dec 2020)");
  script_name("Adobe Lightroom Classic Arbitrary Code ExecutionVulnerability - Windows");

  script_tag(name:"summary", value:"Adobe Lightroom Classic is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an uncontrolled search
  path element.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Lightroom Classic 10.0andearlier
 versions.");

  script_tag(name:"solution", value:"Update Adobe Lightroom Classic 10.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/lightroom/apsb20-74.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_lightroom_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Lightroom/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"10.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);