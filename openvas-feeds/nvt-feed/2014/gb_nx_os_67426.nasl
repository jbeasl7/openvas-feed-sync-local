# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105069");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2014-08-21 11:10:24 +0100 (Thu, 21 Aug 2014)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2013-6975");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco NX-OS Arbitrary File Read Vulnerability (CSCul23419)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in the command-line interface (CLI) of Cisco
  NX-OS Software could allow an authenticated, local attacker to access the contents of arbitrary
  files on the affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cisco NX-OS software contains a directory traversal
  vulnerability within the command line interface that could allow a local, authenticated attacker
  to disclose the contents of arbitrary files on the affected device.");

  script_tag(name:"impact", value:"An attacker could leverage the NX-OS 'copy' command to duplicate
  the contents of arbitrary files on the device to a user writable area of the filesystem.  As the
  new file will be owned by the authenticated user, the attacker will be able to view the
  contents.");

  script_tag(name:"affected", value:"Cisco Nexus 7000, Cisco MDS 9000, Cisco Nexus 6000, Cisco
  Nexus 5500, Cisco Nexus 5000, Cisco Nexus 4000, Cisco Nexus 3500, Cisco Nexus 3000, Cisco Nexus
  1000V, Cisco Connected Grid Router 1000 Series, Cisco Unified Computing System Fabric
  Interconnect 6200 and Cisco Unified Computing System Fabric Interconnect 6100.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67426");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCul23419");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!device = get_kb_item("cisco/nx_os/device"))
  exit(0);

if (device != "Nexus")
  exit(0);

if (!model = get_kb_item("cisco/nx_os/model"))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (model =~ "^1[0-9][0-9][0-9]([Vv])") {
  affected = make_list("4.0(4)SV1(1)",
                       "4.0(4)SV1(2)",
                       "4.0(4)SV1(3)",
                       "4.0(4)SV1(3a)",
                       "4.0(4)SV1(3b)",
                       "4.0(4)SV1(3c)",
                       "4.0(4)SV1(3d)",
                       "4.2(1)SV1(4)",
                       "4.2(1)SV1(4a)",
                       "4.2(1)SV1(4b)",
                       "4.2(1)SV1(5.1)",
                       "4.2(1)SV1(5.1a)",
                       "4.2(1)SV1(5.2)",
                       "4.2(1)SV1(5.2b)",
                       "4.2(1)SV2(1.1)",
                       "4.2(1)SV2(1.1a)",
                       "4.2(1)SV2(2.1)",
                       "4.2(1)SV2(2.1a)",
                       "5.2(1)SM1(5.1)");
}

else if (model =~ "^C?3[0-9][0-9][0-9]") {
  affected = make_list("5.0(3)U1(1)",
                       "5.0(3)U1(1a)",
                       "5.0(3)U1(1b)",
                       "5.0(3)U1(1d)",
                       "5.0(3)U1(2)",
                       "5.0(3)U1(2a)",
                       "5.0(3)U2(1)",
                       "5.0(3)U2(2)",
                       "5.0(3)U2(2a)",
                       "5.0(3)U2(2b)",
                       "5.0(3)U2(2c)",
                       "5.0(3)U2(2d)",
                       "5.0(3)U3(1)",
                       "5.0(3)U3(2)",
                       "5.0(3)U3(2a)",
                       "5.0(3)U3(2b)",
                       "5.0(3)U4(1)",
                       "5.0(3)U5(1)",
                       "5.0(3)U5(1a)",
                       "5.0(3)U5(1b)",
                       "5.0(3)U5(1c)",
                       "5.0(3)U5(1d)",
                       "5.0(3)U5(1e)",
                       "5.0(3)U5(1f)",
                       "5.0(3)U5(1g)",
                       "5.0(3)U5(1h)",
                       "6.0(2)U1(1)",
                       "6.0(2)U1(1a)",
                       "6.0(2)U1(2)",
                       "6.0(2)U1(3)");
}

else if (model =~ "^C?4[0-9][0-9][0-9]") {
  affected = make_list("4.1(2)E1(1)",
                       "4.1(2)E1(1b)",
                       "4.1(2)E1(1d)",
                       "4.1(2)E1(1e)",
                       "4.1(2)E1(1f)",
                       "4.1(2)E1(1g)",
                       "4.1(2)E1(1h)",
                       "4.1(2)E1(1i)",
                       "4.1(2)E1(1j)");
}

else if (model =~ "^C?5[0-9][0-9][0-9]") {
  affected = make_list("4.0(0)N1(1a)",
                       "4.0(0)N1(2)",
                       "4.0(0)N1(2a)",
                       "4.0(1a)N1(1)",
                       "4.0(1a)N1(1a)",
                       "4.0(1a)N2(1)",
                       "4.0(1a)N2(1a)",
                       "4.1(3)N1(1)",
                       "4.1(3)N1(1a)",
                       "4.1(3)N2(1)",
                       "4.1(3)N2(1a)",
                       "4.2(1)N1(1)",
                       "4.2(1)N2(1)",
                       "4.2(1)N2(1a)",
                       "5.0(2)N1(1)",
                       "5.0(3)N1(1c)",
                       "5.0(2)N2(1)",
                       "5.0(2)N2(1a)",
                       "5.0(3)N2(1)",
                       "5.0(3)N2(2)",
                       "5.0(3)N2(2a)",
                       "5.0(3)N2(2b)",
                       "5.1(3)N1(1)",
                       "5.1(3)N1(1a)",
                       "5.1(3)N2(1)",
                       "5.1(3)N2(1a)",
                       "5.1(3)N2(1b)",
                       "5.1(3)N2(1c)",
                       "5.2(1)N1(1)",
                       "5.2(1)N1(1a)",
                       "5.2(1)N1(1b)",
                       "5.2(1)N1(2)",
                       "5.2(1)N1(2a)",
                       "5.2(1)N1(3)",
                       "5.2(1)N1(4)",
                       "5.2(1)N1(5)",
                       "5.2(1)N1(6)",
                       "5.2(1)N1(7)");
}

else if (model =~ "^C?7[0-9][0-9][0-9]") {
  affected = make_list("4.1.(2)",
                       "4.1.(3)",
                       "4.1.(4)",
                       "4.1.(5)",
                       "4.2.(2a)",
                       "4.2(3)",
                       "4.2(4)",
                       "4.2(6)",
                       "4.2(8)",
                       "5.0(2a)",
                       "5.0(3)",
                       "5.0(5)",
                       "5.1(1)",
                       "5.1(1a)",
                       "5.1(3)",
                       "5.1(4)",
                       "5.1(5)",
                       "5.1(6)",
                       "5.2(1)",
                       "5.2(3a)",
                       "5.2(4)",
                       "5.2(5)",
                       "5.2(7)",
                       "5.2(9)",
                       "6.0(1)",
                       "6.0(2)",
                       "6.0(3)",
                       "6.0(4)",
                       "6.1(1)",
                       "6.1(2)",
                       "6.1(3)",
                       "6.1(4)",
                       "6.1(4a)",
                       "6.2(2)",
                       "6.2(2a)",
                       "7.0(0.128)S0");
}

if (!affected)
  exit(99);

foreach af (affected) {
  if( version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
