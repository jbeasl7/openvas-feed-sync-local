# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902634");
  script_version("2022-12-13T10:10:56+0000");
  script_cve_id("CVE-2011-3868");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2011-11-17 17:54:28 +0530 (Thu, 17 Nov 2011)");
  script_name("VMware Fusion UDF File Systems Buffer Overflow Vulnerability (VMSA-2011-0011) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49942");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026139");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0011.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of arbitrary code.");

  script_tag(name:"affected", value:"VMware Fusion 3.1.0 before 3.1.3.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling UDF filesystem images. This can be
  exploited to cause a buffer overflow via a specially crafted ISO image file.");

  script_tag(name:"summary", value:"VMware Fusion is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Update to version 3.1.3 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Fusion/MacOSX/Version"))
  exit(0);

vers = get_kb_item("VMware/Fusion/MacOSX/Version");
if(vers) {
  if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.2")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"3.1.0 - 3.1.2");
    security_message(port: 0, data: report);
  }
}
