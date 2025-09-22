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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817815");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-24428", "CVE-2020-24429", "CVE-2020-24430", "CVE-2020-24431",
                "CVE-2020-24432", "CVE-2020-24433", "CVE-2020-24434", "CVE-2020-24435",
                "CVE-2020-24436", "CVE-2020-24437", "CVE-2020-24438", "CVE-2020-24439",
                "CVE-2020-24427", "CVE-2020-24426");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-09 03:38:00 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 17:58:21 +0530 (Wed, 04 Nov 2020)");
  script_name("Adobe Reader 2017 Security Update (APSB20-67) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader 2017 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due,

  - An improper access control error.

  - An improper input validation error.

  - Signature validation bypass error.

  - Signature verification bypass error.

  - A security feature bypass error.

  - A heap-based buffer overflow error.

  - A race condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to escalate privilege, execute arbitrary code or javascript, disclose
  sensitive information and conduct dynamic library injection.");

  script_tag(name:"affected", value:"Adobe Reader 2017 version prior to
  2017.011.30180.");

  script_tag(name:"solution", value:"Update to Adobe Reader 2017 version
  2017.011.30180 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-67.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30175")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30180(2017.011.30180)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);