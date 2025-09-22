# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800035");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4473");
  script_name("Adobe Flash CS3 SWF Processing Buffer Overflow Vulnerabilities (APSA08-09)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa08-09.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31769");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause
  heap based buffer overflows via specially crafted SWF files.");

  script_tag(name:"affected", value:"Adobe Flash CS3 Professional on Windows.");

  script_tag(name:"insight", value:"The issues are due to boundary errors while processing overly
  long SWF control parameters.");

  script_tag(name:"solution", value:"Update to Adobe Flash CS4 Professional or later.");

  script_tag(name:"summary", value:"Adobe Flash CS3 is prone to multiple buffer overflow
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

uninstall = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
keys = registry_enum_keys(key:uninstall);
foreach key(keys) {
  adobeName = registry_get_sz(key:uninstall + key, item:"DisplayName");
  if("Adobe Flash CS3 Professional" >< adobeName) {
    security_message(port:0, data:"Adobe Flash CS3 Professional is installed on the target host");
    exit(0);
  }
}

exit(99);