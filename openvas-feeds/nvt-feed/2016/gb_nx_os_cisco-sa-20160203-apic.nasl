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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105547");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-02-15 18:02:24 +0100 (Mon, 15 Feb 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:06:00 +0000 (Tue, 06 Dec 2016)");

  script_cve_id("CVE-2016-1302");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco NX-OS Application Policy Infrastructure Controller Access Control Vulnerability (cisco-sa-20160203-apic)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in the role-based access control (RBAC) of the
  Cisco Application Policy Infrastructure Controller (APIC) could allow an authenticated remote
  user to make configuration changes outside of their configured access privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to eligibility logic in the RBAC
  processing code. An authenticated user could exploit this vulnerability by sending specially
  crafted representational state transfer (REST) requests to the APIC.");

  script_tag(name:"impact", value:"An exploit could allow the authenticated user to make
  configuration changes to the APIC beyond the configured privilege for their role.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160203-apic");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if( ! device = get_kb_item( "cisco/nx_os/device" ) )
  exit( 0 );

if( "Nexus" >!< device )
  exit( 0 );

if ( ! nx_model = get_kb_item( "cisco/nx_os/model" ) )
  exit( 0 );

if( nx_model !~ "^C?9[0-9]{3}" )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

vers = ereg_replace( pattern:'[()]', replace:".", string:version );
vers = ereg_replace( pattern:'\\.$', replace:"", string:vers );

if( version =~ "^11\.0" && revcomp( a:vers, b: "11.0.3h" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.0(3h)" );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version =~ "^11\.1" && revcomp( a:vers, b:"11.1.1j" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.1(1j)" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
