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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807524");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-03-15 13:16:16 +0530 (Tue, 15 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:20:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-1329");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Nexus 3000 Series and 3500 Platform Switches Insecure Default Credentials Vulnerability (cisco-sa-20160302-n3k)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in Cisco NX-OS Software running on Cisco Nexus
  3000 Series Switches and Cisco Nexus 3500 Platform Switches could allow an unauthenticated,
  remote attacker to log in to the device with the privileges of the root user with bash shell
  access.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a user account that has a default
  and static password. This account is created at installation and cannot be changed or deleted
  without impacting the functionality of the system. An attacker could exploit this vulnerability
  by connecting to the affected system using this default account. The account can be used to
  authenticate remotely to the device via Telnet (or SSH on a specific release) and locally on the
  serial console.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-n3k");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! device = get_kb_item( "cisco/nx_os/device" ) )
  exit( 0 );

if( "Nexus" >!< device )
  exit( 0 );

if ( ! nx_model = get_kb_item( "cisco/nx_os/model" ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( nx_model !~ "^C?3[05]" )
  exit( 99 );

if( nx_model =~ "^C?30") {
  if( version  == "6.0(2)U6(1)" )
    fix = "6.0(2)U6(1a)";
  else if( version == "6.0(2)U6(2)" )
    fix = "6.0(2)U6(2a)";
  else if( version == "6.0(2)U6(3)" )
    fix = "6.0(2)U6(3a)";
  else if( version == "6.0(2)U6(4)" )
    fix = "6.0(2)U6(4a)";
  else if( version == "6.0(2)U6(5)" )
    fix = "6.0(2)U6(5a)";
}

else if( nx_model =~ "^C?35") {
  if( version == "6.0(2)A6(1)" )
    fix = "6.0(2)A6(1a)";
  else if( version == "6.0(2)A6(2)" )
    fix = "6.0(2)A6(2a)";
  else if( version == "6.0(2)A6(3)" )
    fix = "6.0(2)A6(3a)";
  else if( version == "6.0(2)A6(4)" )
    fix = "6.0(2)A6(4a)";
  else if( version == "6.0(2)A6(5)" )
    fix = "6.0(2)A6(5a)";
  else if( version == "6.0(2)A7(1)" )
    fix = "6.0(2)A7(1a)";
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
