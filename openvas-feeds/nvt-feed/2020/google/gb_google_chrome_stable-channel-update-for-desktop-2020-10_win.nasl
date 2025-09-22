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
  script_oid("1.3.6.1.4.1.25623.1.0.817506");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970",
                "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15990", "CVE-2020-15991",
                "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976",
                "CVE-2020-6557", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979",
                "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983",
                "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987",
                "CVE-2020-15992", "CVE-2020-15988", "CVE-2020-15989");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-11 18:01:00 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-10-07 15:53:01 +0530 (Wed, 07 Oct 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2020-10) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Use after free in payments.

  - Use after free in Blink.

  - Use after free in WebRTC.

  - Use after free in NFC.

  - Use after free in printing.

  - Use after free in audio.

  - Use after free in autofill.

  - Use after free in password manager.

  - Insufficient policy enforcement in extensions.

  - Integer overflow in Blink.

  - Integer overflow in SwiftShader.

  - Use after free in WebXR.

  - Inappropriate implementation in networking.

  - Insufficient data validation in dialogs.

  - Insufficient data validation in navigation.

  - Inappropriate implementation in V8.

  - Insufficient policy enforcement in Intents.

  - Out of bounds read in audio.

  - Side-channel information leakage in cache.

  - Insufficient data validation in webUI.

  - Insufficient policy enforcement in Omnibox.

  - Inappropriate implementation in Blink.

  - Integer overflow in media.

  - Insufficient policy enforcement in networking.

  - Insufficient policy enforcement in downloads.

  - Uninitialized Use in PDFium.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Google Chrome version  prior to 86.0.4240.75.");

  script_tag(name:"solution", value:"Update to Google Chrome version 86.0.4240.75 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/10/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"86.0.4240.75")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"86.0.4240.75", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);