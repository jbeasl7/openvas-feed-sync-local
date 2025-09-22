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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801322");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1140");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Products USB Service Local Privilege Escalation Vulnerability (CVE-2010-1140) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39397");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-04/0121.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to modify arbitrary memory
  locations in guest kernel memory and gain privileges.");

  script_tag(name:"affected", value:"VMware Player 3.0 before 3.0.1 build 227600,
  VMware Workstation 7.0 before 7.0.1 build 227600 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in 'USB' service which allows host OS users to gain
  privileges by placing a Trojan horse program at an unspecified location on the host OS disk.");

  script_tag(name:"summary", value:"VMware products are prone to a local privilege escalation vulnerability.");

  script_tag(name:"solution", value:"Update to:

  - VMware Player 3.0.1 build 227600

  - VMware Workstation 7.0.1 build 227600");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed"))
  exit(0);

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer) {
  if(version_is_less_equal(version:vmplayerVer, test_version:"3.0.0")) {
    report = report_fixed_ver(installed_version:vmplayerVer, vulnerable_range:"Less or equal to 3.0.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer) {
  if(version_is_less_equal(version:vmworkstnVer, test_version:"7.0.0")) {
    report = report_fixed_ver(installed_version:vmworkstnVer, vulnerable_range:"Less or equal to 7.0.0");
    security_message(port: 0, data: report);
  }
}
