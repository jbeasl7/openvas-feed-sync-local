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
  script_oid("1.3.6.1.4.1.25623.1.0.817130");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-9815", "CVE-2020-9788", "CVE-2020-9831", "CVE-2020-9852",
                "CVE-2020-9856", "CVE-2020-9855", "CVE-2020-3882", "CVE-2020-9793",
                "CVE-2020-9844", "CVE-2020-9804", "CVE-2020-9791", "CVE-2020-9792",
                "CVE-2020-9827", "CVE-2020-9794", "CVE-2020-9824", "CVE-2020-9825",
                "CVE-2020-9851", "CVE-2020-3878");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-09 16:00:00 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-05-27 12:16:54 +0530 (Wed, 27 May 2020)");
  script_name("Apple Mac OS X Security Update (HT211170) - 01");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - Insufficient input sanitization.

  - An integer overflow.

  - Insufficient validation of symlinks.

  - A memory corruption issue.

  - A double free error.

  - A logic issue.

  - An error in sandbox restrictions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, execute arbitrary javascript code, gain access to
  sensitive information, gain elevated privileges, conduct a DoS attck, modify
  restricted network settings and bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.15.x through 10.15.4");

  script_tag(name:"solution", value:"Update to Apple Mac OS X 10.15.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211170");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName)
  exit(0);

if(osVer =~ "^10\.15") {
  if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.4")) {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.15.5");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);