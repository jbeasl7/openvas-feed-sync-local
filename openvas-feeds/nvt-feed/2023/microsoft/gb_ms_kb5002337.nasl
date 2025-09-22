# Copyright (C) 2023 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826769");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-21741", "CVE-2023-21736", "CVE-2023-21737");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-10 22:15:00 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 09:52:21 +0530 (Wed, 11 Jan 2023)");
  script_name("Microsoft Visio 2016 Multiple Vulnerabilities (KB5002337)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002337.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple remote
  code execution and information disclosure vulnerabilities in Microsoft Visio.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Microsoft Visio 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002337");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", item:"Path");
if(!sysPath)
  exit(0);

version = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(!version)
  exit(0);

if(version_in_range(version:version, test_version:"16.0", test_version2:"16.0.5378.0999")) {
  report = report_fixed_ver(file_checked:"visio.exe", file_version:version, vulnerable_range:"16.0 - 16.0.5378.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
