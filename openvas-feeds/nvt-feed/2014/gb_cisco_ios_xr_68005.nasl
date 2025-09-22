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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105080");
  script_version("2022-09-26T10:10:50+0000");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"creation_date", value:"2014-09-04 10:43:53 +0200 (Thu, 04 Sep 2014)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2014-2176");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IOS XR Software IPv6 Packet Handling Denial of Service Vulnerability (cisco-sa-20140611-ipv6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ios_xr_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xr/detected", "cisco/ios_xr/model");

  script_tag(name:"summary", value:"Cisco IOS XR is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue is being tracked by Cisco Bug ID CSCun71928");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause NP chip and a line
  card on an affected device to lockup and reload, denying service to legitimate users.");

  script_tag(name:"affected", value:"This issue is being tracked by Cisco Bug ID CSCun71928.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68005");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140611-ipv6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! model = get_kb_item( "cisco/ios_xr/model" ) )
  exit( 0 );

if( "ASR9K" >!< model )
  exit( 99 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version =~ "^3\.[79]\.[0-3]$" || version =~ "^3\.8\.[0-4]$" || version =~ "^4\.0\.[0-4]$" ||
    version =~ "^4\.1\.[0-2]$" || version =~ "^4\.2\.[0-4]$" || version =~ "^4\.3\.[0-4]$" ||
    version =~ "^5\.1\.[01]$" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
