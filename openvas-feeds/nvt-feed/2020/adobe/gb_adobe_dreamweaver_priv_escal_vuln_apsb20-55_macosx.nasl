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

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817608");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-24425");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 12:58:00 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 11:26:46 +0530 (Wed, 21 Oct 2020)");
  script_name("Adobe Dreamweaver Privilege Escalation Vulnerability (APSB20-55) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Dreamweaver is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to presence of an
  uncontrolled search path element.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to
  gain elevated privileges on the affected system.");

  script_tag(name:"affected", value:"Adobe Dreamweaver 20.2 and prior.");

  script_tag(name:"solution", value:"Update to Adobe Dreamweaver 21.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb20-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_dreamweaver_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Dreamweaver/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"21.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
