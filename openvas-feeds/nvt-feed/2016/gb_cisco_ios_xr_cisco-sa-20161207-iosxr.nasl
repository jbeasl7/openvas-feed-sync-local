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
  script_oid("1.3.6.1.4.1.25623.1.0.106450");
  script_version("2022-09-23T10:10:45+0000");
  script_tag(name:"last_modification", value:"2022-09-23 10:10:45 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-12-08 15:09:24 +0700 (Thu, 08 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 18:32:00 +0000 (Thu, 22 Dec 2016)");

  script_cve_id("CVE-2016-9215");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IOS XR Software Default Credentials Vulnerability (cisco-sa-20161207-iosxr)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ios_xr_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xr/detected");

  script_tag(name:"summary", value:"A vulnerability in Cisco IOS XR Software could allow an
  authenticated, local attacker to log in to the device with the privileges of the root user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a user account that has a default
  and static password. An attacker could exploit this vulnerability by connecting to the affected
  system using this default account.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to log in with the default
  credentials, allowing the attacker to gain complete control of the underlying operating system.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-iosxr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version == "6.1.1" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
