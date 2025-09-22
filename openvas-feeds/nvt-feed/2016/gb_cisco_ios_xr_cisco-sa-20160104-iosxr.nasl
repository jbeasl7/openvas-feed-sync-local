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
  script_oid("1.3.6.1.4.1.25623.1.0.105529");
  script_version("2022-09-23T10:10:45+0000");
  script_tag(name:"last_modification", value:"2022-09-23 10:10:45 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-01-26 15:02:08 +0100 (Tue, 26 Jan 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:20:00 +0000 (Wed, 07 Dec 2016)");

  script_cve_id("CVE-2015-6432");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IOS XR Software OSPF Link State Advertisement PCE Vulnerability (cisco-sa-20160104-iosxr)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ios_xr_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xr/detected");

  script_tag(name:"summary", value:"A vulnerability in Open Shortest Path First (OSPF) Link State
  Advertisement (LSA) handling by Cisco IOS XR Software could allow an unauthenticated, remote
  attacker to cause a denial of service (DoS) condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the number of OSPF Path Computation
  Elements (PCEs) that are configured for an OSPF LSA opaque area update. An attacker could exploit
  this vulnerability by sending a crafted OSPF LSA update to an affected device that is running the
  vulnerable software and OSPF configuration.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a DoS
  condition due to the OSPF process restarting when the crafted OSPF LSA update is received.");

  script_tag(name:"affected", value:"Cisco IOS XR Software Releases 4.1.1, 4.2.0, 4.2.3, 4.3.0,
  4.3.2, 5.0.0, 5.1.0, 5.2.0, 5.2.2, 5.2.4, 5.3.0, and 5.3.2.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160104-iosxr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list( "4.1.1", "4.2.0", "4.2.3", "4.3.0", "4.3.2",
                      "5.0.0", "5.1.0", "5.2.0", "5.2.2", "5.2.4", "5.3.0", "5.3.2" );

foreach af ( affected ) {
  if( version == af ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See vendor advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
