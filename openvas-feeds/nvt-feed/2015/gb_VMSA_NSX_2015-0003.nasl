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

CPE = "cpe:/a:vmware:nsx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105424");
  script_cve_id("CVE-2014-6593");
  script_version("2022-03-15T10:34:45+0000");
  script_name("VMware NSX updates address critical information disclosure issue in JRE (VMSA-2015-0003)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-03-15 10:34:45 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-10-27 17:31:18 +0100 (Tue, 27 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_nsx_consolidation.nasl");
  script_mandatory_keys("vmware/nsx/detected");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0003.html");

  script_tag(name:"summary", value:"VMware NSX updates address critical information disclosure issue
  in JRE.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/build is present on the target host.");

  script_tag(name:"insight", value:"Oracle JRE is updated in VMware products to address a critical
  security issue that existed in earlier releases of Oracle JRE.");

  script_tag(name:"affected", value:"NSX for vSphere prior 6.1.4 Build 2691049

  NSX for Multi-Hypervisor prior to 4.2.4 Build 42965");

  script_tag(name:"solution", value:"Apply the missing update.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/nsx/build" ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"4.2", test_version2:"4.2.3" ) )
  fix = "4.2.4-42965";

if( version =~ "^4\.2\.4" ) {
  if( int( build ) < int( 42965 ) )
    fix = "4.2.4-42965";
}

if( version_in_range( version:version, test_version:"6.1", test_version2:"6.1.3" ) )
  fix = "6.1.4-2691049";

if( version =~ "^6\.1\.4" ) {
  if( int( build ) < int( 2691049 ) )
    fix = "6.1.4-2691049";
}

if( fix ) {
  report = report_fixed_ver( installed_version:version + "-" + build, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
