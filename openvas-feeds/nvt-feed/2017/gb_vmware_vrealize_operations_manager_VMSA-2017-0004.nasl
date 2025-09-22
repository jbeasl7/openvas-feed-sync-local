# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:vrealize_operations_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140229");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-31 10:25:48 +0200 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:58:42 +0000 (Thu, 25 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Operations Apache Struts2 RCE Vulnerability (VMSA-2017-0004)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_operations_manager_http_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/detected", "vmware/vrealize/operations_manager/build");

  script_tag(name:"summary", value:"VMware vRealize Operations is prone to a remote code execution
  (RCE) vulnerability in Apache Struts2.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may result in the complete
  compromise of an affected product.");

  script_tag(name:"affected", value:"VMware vRealize Operations version 6.2.1, 6.3, 6.4 and 6.5.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0004.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vrealize/operations_manager/build" ) )
  exit( 0 );

if( version =~ "^6\.3\.0" )
  if( int( build ) < int( 5263486 ) ) fix = '6.3.0 Build 5263486';

if( version =~ "^6\.2\.1" )
  if( int( build ) < int( 5263486 ) ) fix = '6.2.1 Build 5263486';

if( version =~ "^6\.4\.0" )
  if( int( build ) < int( 5263486 ) ) fix = '6.4.0 Build 5263486';

if( version =~ "^6\.5\.0" )
  if( int( build ) < int( 5263486 ) ) fix = '6.5.0 Build 5263486';


if( fix ) {
  report = report_fixed_ver( installed_version:version + ' Build ' + build, fixed_version:fix );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );
