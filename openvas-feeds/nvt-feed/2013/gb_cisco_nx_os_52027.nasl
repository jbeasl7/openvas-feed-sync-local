# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103801");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-10-10 11:38:56 +0200 (Thu, 10 Oct 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2012-0352");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco NX-OS Malformed IP Packet Denial of Service Vulnerability (cisco-sa-20120215-nxos)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"Cisco NX-OS Software is affected by a denial of service (DoS)
  vulnerability that could cause Cisco Nexus 1000v, 1010, 5000, and 7000 Series Switches, and the
  Cisco Virtual Security Gateway (VSG) for Nexus 1000V Series Switches, that are running affected
  versions of Cisco NX-OS Software to reload when the IP stack processes a malformed IP packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is in the operating system's IP stack and any
  feature that makes use of services offered by the IP stack to parse IP packets is affected. For
  instance, the following scenarios may trigger the vulnerability because they imply that Layer 4
  (UDP or TCP) information is required to be able to perform the configured function:

  - A malformed, transit IP packet that would normally be forwarded by the switch is received and
  the Time-to-live (TTL) is 1. In this case, an ICMP error message (time exceeded) needs to be
  generated. During generation of this ICMP message, the bug could be triggered.

  - Policy-based routing is in use, and to make a routing decision, an incoming packet needs to be
  parsed. If the packet is a malformed TCP segment and the routing policy uses TCP information for
  routing decisions, then this bug could be triggered.

  - An egress Access Control List (ACL) is applied to an interface and a malformed IP packet that
  needs to be forwarded through that interface is received.

  Note: This list is not exhaustive. It contains some of the scenarios that have been confirmed to
  trigger the vulnerability described in this document. Other scenarios that require accessing
  Layer 4 information of a malformed IP packet may also result in the vulnerability being
  triggered.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the device to crash,
  denying service to legitimate users.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52027");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/ps9902/tsd_products_support_series_home.html");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/ps9670/");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120215-nxos");

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

affected = FALSE;

if (model =~ "^1000[Vv]") {
  affected = make_list("4.2(1)sv1(4a)",
                       "4.2(1)sv1(4)",
                       "4.0(4)sv1(1)",
                       "4.0(4)sv1(2)",
                       "4.0(4)sv1(3)",
                       "4.0(4)sv1(3a)",
                       "4.0(4)sv1(3b)",
                       "4.0(4)sv1(3c)",
                       "4.0(4)sv1(3d)",
                       "4.2(1)n2(1a)",
                       "4.1(3)n1(1a)",
                       "4.1(3)n1(1)",
                       "4.0(1a)n2(1a)",
                       "4.0(1a)n2(1)",
                       "4.0(1a)n1(1a)",
                       "4.0(1a)n1(1)",
                       "4.0(0)n1(2a)",
                       "4.0(0)n1(1a)",
                       "4.0(0)n1(2)",
                       "4.2(1)n2(1)",
                       "4.2(1)n1(1)",
                       "4.1(3)n2(1a)",
                       "4.1(3)n2(1)");
}

else if (model =~ "^C?5") {
  affected = make_list("5.1(3)n1(1a)",
                       "5.0(3)n2(2b)",
                       "5.0(3)n2(2a)",
                       "5.0(3)n2(2)",
                       "5.0(3)n2(1)",
                       "5.0(3)n1(1c)",
                       "5.1(3)n1(1)",
                       "5.0(2)n2(1a)",
                       "5.0(2)n2(1)",
                       "5.0(3)n1(1b)",
                       "5.0(3)n1(1a)",
                       "5.0(3)n1(1)");
}

else if (model =~ "^C?7") {
  affected = make_list("5.0(3)n1(1)",
                       "4.2(6)",
                       "4.2(3)",
                       "4.2(4)",
                       "4.2.(2a)",
                       "5.0(3)",
                       "5.0(2a)",
                       "4.2(1)",
                       "4.2(2)",
                       "5.0(2)",
                       "5.1(2)",
                       "4.1.(2)",
                       "4.1.(3)",
                       "4.1.(4)",
                       "4.1.(5)",
                       "5.1(6)",
                       "5.1(1a)",
                       "5.1(3)",
                       "5.1(4)",
                       "5.1(5)");
}

if (affected) {
  foreach af (affected) {
    if (version == af) {
      report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
