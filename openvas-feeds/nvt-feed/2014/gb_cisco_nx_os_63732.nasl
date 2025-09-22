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
  script_oid("1.3.6.1.4.1.25623.1.0.105109");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2014-11-05 16:22:05 +0100 (Wed, 05 Nov 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2013-5556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Nexus 1000V Series Switches Arbitrary Command Execution Vulnerability (Cisco-SA-20131115-CVE-2013-5556)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in the license installation module of the Cisco
  Nexus 1000V could allow an authenticated, local attacker to execute arbitrary shell commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a failure of the install all iso
  command to properly validate user-supplied input. An attacker could exploit this vulnerability by
  providing crafted arguments to the install all iso command.

  To exploit this vulnerability, an attacker would need local access to the targeted device, which
  decreases the likelihood of a successful exploit.");

  script_tag(name:"affected", value:"Cisco Nexus 1000V.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63732");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20131115-CVE-2013-5556.html");

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

if (model != "1000V")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

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
                     "5.2(1)SM1(5.1)",
                     "4.2(1) VSG1(1)");

foreach af (affected) {
  if( version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
