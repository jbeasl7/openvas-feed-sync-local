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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105595");
  script_version("2022-03-10T09:57:15+0000");
  script_tag(name:"last_modification", value:"2022-03-10 09:57:15 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-04-04 12:02:56 +0200 (Mon, 04 Apr 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-12 01:29:00 +0000 (Fri, 12 May 2017)");

  script_cve_id("CVE-2016-1350");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager Software Session Initiation Protocol Memory Leak Vulnerability (cisco-sa-20160323-sip)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_consolidation.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP)
  gateway implementation in Cisco Unified Communications Manager Software could allow an
  unauthenticated, remote attacker to cause a memory leak and eventual reload of an affected
  device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper processing of malformed
  SIP messages. An attacker could exploit this vulnerability by sending malformed SIP messages to
  be processed by an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a memory leak and
  eventual reload of the affected device.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager 8.x < 9.1(2)su4 /
  10.5(2)su3 / 11.0(1)su1");

  script_tag(name:"solution", value:"Update to version 9.1(2)su4, 10.5(2)su3, 11.0(1)su1 or later.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

if( vers =~ "^8\." )
  fix = "9.1(2)su4";

if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.1.2.10000.28" ) )
  fix = "9.1(2)su4";

if( version_in_range( version:vers, test_version:"10.0", test_version2:"10.5.2.10000.5" ) )
  fix = "10.5(2)su3";

if( version_in_range( version:vers, test_version:"11.0", test_version2:"11.0.1.10000.10" ) )
  fix = "11.0(1)su1";

if( fix ) {
  report = report_fixed_ver(  installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
