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
  script_oid("1.3.6.1.4.1.25623.1.0.103879");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2014-01-13 10:35:00 +0100 (Mon, 13 Jan 2014)");

  script_cve_id("CVE-2013-6982");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco NX-OS Software Crafted Border Gateway Protocol Update Message Denial of Service Vulnerability (Cisco-SA-20140106-CVE-2013-6982)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in the Border Gateway Protocol (BGP)
  functionality of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause
  all BGP sessions on the device to reset.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the improper processing of
  specifically crafted BGP update messages. An attacker could exploit this vulnerability by
  crafting a specific BGP-labeled update message.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause all the BGP peers
  on a Cisco NX-OS device that are configured with either a VPNv4, VPNv6, or IPv6 labeled unicast
  address family to reset.");

  script_tag(name:"affected", value:"Cisco Nexus 7000 running NX-OS 6.2(2)S27.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64670");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20140106-CVE-2013-6982.html");

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

if (model !~ "^C?7")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version == "6.2(2)S27") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0(0)ZD(0.132)");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
