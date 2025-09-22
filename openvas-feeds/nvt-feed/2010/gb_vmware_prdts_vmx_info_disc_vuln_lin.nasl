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
  script_oid("1.3.6.1.4.1.25623.1.0.801321");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1138");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("VMware Products 'vmware-vmx' Information Disclosure Vulnerability (VMSA-2010-0007) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39395");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39206");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0007.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2010/000090.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially sensitive
  information.");

  script_tag(name:"affected", value:"VMware Server 2.x

  VMware Player 3.0 before 3.0.1 build 227600

  VMware Player 2.5.x before 2.5.4 build 246459

  VMware Workstation  7.0 before 7.0.1 build 227600

  VMware Workstation 6.5.x before 6.5.4 build 246459

  VMware ACE 2.6 before 2.6.1 build 227600 and 2.5.x before 2.5.4 build 246459 on Linux");

  script_tag(name:"insight", value:"The flaw is due to error in 'virtual networking stack' when interacting between the
  guest OS and host 'vmware-vmx' process, which allows attackers to obtain sensitive
  information from memory on the host OS by examining received network packets.");

  script_tag(name:"summary", value:"VMware products are prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply the updated provided by the vendor.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed"))
  exit(0);

vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer) {
  if(version_is_equal(version:vmplayerVer, test_version:"3.0.0") ||
     version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.3")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer) {
  if(version_is_equal(version:vmworkstnVer, test_version:"7.0.0") ||
     version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.3")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmserVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserVer) {
  if(vmserVer =~ "^2\.") {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
