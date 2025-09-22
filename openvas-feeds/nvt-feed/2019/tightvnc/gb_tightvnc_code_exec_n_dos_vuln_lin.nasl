# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:tightvnc:tightvnc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815831");
  script_version("2021-10-08T15:01:22+0000");
  script_cve_id("CVE-2019-8287", "CVE-2019-15678", "CVE-2019-15679", "CVE-2019-15680");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-08 15:01:22 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-09 17:15:00 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2019-11-08 12:29:11 +0530 (Fri, 08 Nov 2019)");
  script_name("TightVNC <= 1.3.10 Multiple Vulnerabilities - Linux");

  script_tag(name:"summary", value:"TightVNC is prone multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A  heap buffer overflow in InitialiseRFBConnection function.

  - A null pointer dereference in HandleZlibBPP function.

  - A global buffer overflow in HandleCoRREBBP macro function.

  - A heap buffer overflow in rfbServerCutText handler.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and cause denial of service condition.");

  script_tag(name:"affected", value:"TightVNC version 1.3.10 and earlier.");

  script_tag(name:"solution", value:"Update to version 2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/12/10/5");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_tightvnc_detect_lin.nasl");
  script_mandatory_keys("TightVNC/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"1.3.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);