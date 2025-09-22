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


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817425");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513",
                "CVE-2020-6514", "CVE-2020-6515", "CVE-2020-6516", "CVE-2020-6517",
                "CVE-2020-6518", "CVE-2020-6519", "CVE-2020-6520", "CVE-2020-6521",
                "CVE-2020-6522", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6525",
                "CVE-2020-6526", "CVE-2020-6527", "CVE-2020-6528", "CVE-2020-6529",
                "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6533", "CVE-2020-6534",
                "CVE-2020-6535", "CVE-2020-6536");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-12 21:59:00 +0000 (Fri, 12 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-08-12 14:16:02 +0530 (Wed, 12 Aug 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2020-07) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Heap buffer overflow in background fetch.

  - Side-channel information leakage in content security policy.

  - Type Confusion in V8.

  - Heap buffer overflow in PDFium.

  - Inappropriate implementation in WebRTC.

  - Use after free in tab strip.

  - Policy bypass in CORS.

  - Heap buffer overflow in history.

  - Use after free in developer tools.

  - Policy bypass in CSP.

  - Heap buffer overflow in Skia.

  - Side-channel information leakage in autofill.

  - Inappropriate implementation in external protocol handlers.

  - Out of bounds write in Skia.

  - Heap buffer overflow in WebAudio.

  - Inappropriate implementation in iframe sandbox.

  - Insufficient policy enforcement in CSP.

  - Incorrect security UI in basic auth.

  - Out of bounds memory access in developer tools.

  - Side-channel information leakage in scroll to text.

  - Heap buffer overflow in WebRTC.

  - Insufficient data validation in WebUI.

  - Incorrect security UI in PWAs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 84.0.4147.89.");

  script_tag(name:"solution", value:"Update to Google Chrome version 84.0.4147.89 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/07/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"84.0.4147.89")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"84.0.4147.89", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);