# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902146");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0164", "CVE-2010-0165", "CVE-2010-0170", "CVE-2010-0172");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Mar 2010) - Linux");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=547143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38918");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-09.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-10.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to cause Denial of Service and conduct
  cross site scripting attacks.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.6 before 3.6.2.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An use-after-free error in the 'imgContainer::InternalAddFrameHelper'
     function in 'src/imgContainer.cpp' in 'libpr0n', allows to cause denial of service
     via a multipart/x-mixed-replace animation.

  - An error in 'TraceRecorder::traverseScopeChain()' within 'js/src/jstracer.cpp'
     allows to cause a memory corruption via vectors involving certain indirect
     calls to the JavaScript eval function.

  - An error while offering plugins in expected window which allows to conduct
     cross site scripting attacks via vectors that are specific to each affected
     plugin.");
  script_tag(name:"solution", value:"Update to version 3.6.2 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"3.6", test_version2:"3.6.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.2", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
