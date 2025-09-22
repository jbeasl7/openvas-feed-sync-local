# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803021");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-0547");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-09-03 12:12:23 +0530 (Mon, 03 Sep 2012)");
  script_name("Oracle Java SE JRE AWT Component Unspecified Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55339");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027458");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/alert-cve-2012-4681.html");

  script_tag(name:"impact", value:"Has no impact and remote attack vectors. The missing patch is a
  security-in-depth fix released by Oracle.");

  script_tag(name:"affected", value:"Oracle Java SE versions 7 Update 6, 6 Update 34 and earlier.");

  script_tag(name:"insight", value:"Unspecified vulnerability in the JRE component related to AWT
  sub-component.

  Remark: NIST don't see 'security-in-depth fixes' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a missing
  security update.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to an unspecified vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Sun/Java/JRE/Win/Ver"))
  exit(0);

if(version_in_range(version:vers, test_version:"1.7", test_version2:"1.7.0.6") ||
   version_in_range(version:vers, test_version:"1.6", test_version2:"1.6.0.34")) {
  security_message(port:0);
  exit(0);
}

exit(99);