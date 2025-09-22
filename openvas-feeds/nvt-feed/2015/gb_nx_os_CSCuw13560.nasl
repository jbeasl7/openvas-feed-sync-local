# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105377");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-09-21 11:41:15 +0200 (Mon, 21 Sep 2015)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2015-6295");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Cisco Nexus 9000 Series Switches Reserved VLAN Number Vulnerability (Cisco-SA-20150916-CVE-2015-6295)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in the handling of incoming Layer 2 packets
  tagged with a Cisco Nexus 9000 Series Switch (N9K) reserved VLAN number could allow an
  unauthenticated, adjacent attacker to cause a partial denial of service (DoS) condition due to
  increased CPU utilization and possible control plane instability. In addition, Layer 2 packets,
  which should be dropped by the switch, may be incorrectly forwarded to the connected interfaces.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to lack of validation of the VLAN
  number in the Layer 2 packet. An attacker could exploit this vulnerability by sending a crafted
  Layer 2 packet tagged with an N9K reserved VLAN number.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a partial DoS
  condition due to increased CPU utilization and possible control plane instability. In addition,
  this packet should be dropped by the N9K, but could be forwarded to the attached networks.");

  script_tag(name:"affected", value:"Nexus 9000 Series 7.0(3)I1(1) and 6.1(2)I3(4).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20150916-CVE-2015-6295.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76762");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! device = get_kb_item( "cisco/nx_os/device" ) )
  exit( 0 );

if( device != "Nexus" )
  exit( 0 );

if( ! nx_model = get_kb_item( "cisco/nx_os/model" ) )
  exit( 0 );

if( nx_model !~ "^C?9[0-9]{3}" )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( version  == "6.1(2)I3(4)" || version == "7.0(3)I1(1)" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
