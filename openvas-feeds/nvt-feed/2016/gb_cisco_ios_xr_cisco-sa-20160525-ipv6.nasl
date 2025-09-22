# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105736");
  script_version("2022-09-23T10:10:45+0000");
  script_tag(name:"last_modification", value:"2022-09-23 10:10:45 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-05-30 11:07:17 +0200 (Mon, 30 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-1409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Products IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability (cisco-sa-20160525-ipv6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ios_xr_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xr/detected");

  script_tag(name:"summary", value:"A vulnerability in the IP Version 6 (IPv6) packet processing
  functions of multiple Cisco products could allow an unauthenticated, remote attacker to cause an
  affected device to stop processing IPv6 traffic, leading to a denial of service (DoS) condition
  on the device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient processing logic for
  crafted IPv6 packets that are sent to an affected device. An attacker could exploit this
  vulnerability by sending crafted IPv6 Neighbor Discovery packets to an affected device for
  processing.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the
  device to stop processing IPv6 traffic, leading to a DoS condition on the device.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160525-ipv6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list(
  '2.0.0',
  '3.0.0',
  '3.0.1',
  '3.2.0',
  '3.2.1',
  '3.2.2',
  '3.2.3',
  '3.2.4',
  '3.2.50',
  '3.2.6',
  '3.3.0',
  '3.3.1',
  '3.3.2',
  '3.3.3',
  '3.3.4',
  '3.4.0',
  '3.4.1',
  '3.4.2',
  '3.4.3',
  '3.5.0',
  '3.5.2',
  '3.5.3',
  '3.5.4',
  '3.6 Base',
  '3.6.1',
  '3.6.2',
  '3.6.3',
  '3.6.0',
  '3.7 Base',
  '3.7.1',
  '3.7.2',
  '3.7.3',
  '3.7.0',
  '3.8.0',
  '3.8.1',
  '3.8.2',
  '3.8.3',
  '3.8.4',
  '3.9.0',
  '3.9.1',
  '3.9.2',
  '3.9.3',
  '4.0 Base',
  '4.0.0',
  '4.0.1',
  '4.0.2',
  '4.0.3',
  '4.0.4',
  '4.0.11',
  '4.1 Base',
  '4.1.0',
  '4.1.1',
  '4.1.2',
  '4.2.0',
  '4.2.1',
  '4.2.2',
  '4.2.3',
  '4.2.4',
  '4.3.0',
  '4.3.1',
  '4.3.2',
  '4.3.3',
  '4.3.4',
  '5.1.0',
  '5.1.1',
  '5.1.2',
  '5.1.1.K9SEC',
  '5.1.3',
  '5.2.0',
  '5.2.1',
  '5.2.2',
  '5.2.4',
  '5.2.3',
  '5.2.5',
  '5.3.0',
  '5.3.1',
  '5.3.2',
  '5.0 Base',
  '5.0.0',
  '5.0.1' );

foreach af ( affected ) {
  if( version == af ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
