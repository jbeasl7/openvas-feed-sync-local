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
  script_oid("1.3.6.1.4.1.25623.1.0.817041");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-6493", "CVE-2020-6494", "CVE-2020-6495", "CVE-2020-6496",
                "CVE-2020-6497", "CVE-2020-6498");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-02 12:15:00 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 12:29:03 +0530 (Fri, 05 Jun 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2020-06) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Use after free in WebAuthentication.

  - Incorrect security UI in payments.

  - Insufficient policy enforcement in developer tools.

  - Use after free in payments.

  - Insufficient policy enforcement in Omnibox.

  - Incorrect security UI in progress display.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to conduct a denial-of-service or execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 83.0.4103.97.");

  script_tag(name:"solution", value:"Update to Google Chrome version
  83.0.4103.97 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/06/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"83.0.4103.97")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"83.0.4103.97", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);