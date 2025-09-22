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

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105135");
  script_cve_id("CVE-2014-3797", "CVE-2014-8371", "CVE-2013-2877", "CVE-2014-0191", "CVE-2014-0015",
                "CVE-2014-0138", "CVE-2013-1752", "CVE-2013-4238");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("2021-09-28T06:32:28+0000");
  script_name("VMware Security Updates for vCenter Server (VMSA-2014-0012)");
  script_tag(name:"last_modification", value:"2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"creation_date", value:"2014-12-05 11:33:51 +0100 (Fri, 05 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_server_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/server/detected", "vmware/vcenter/server/build");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. VMware vCSA cross-site scripting vulnerability

  VMware vCenter Server Appliance (vCSA) contains a vulnerability that may allow for Cross Site
  Scripting. Exploitation of this vulnerability in vCenter Server requires tricking a user to click
  on a malicious link or to open a malicious web page while they are logged in into vCenter.

  b. vCenter Server certificate validation issue

  vCenter Server does not properly validate the presented certificate when establishing a connection
  to a CIM Server residing on an ESXi host. This may allow for a Man-in-the-middle attack against
  the CIM service.

  c. Update to ESXi libxml2 package

  libxml2 is updated to address multiple security issues.

  d. Update to ESXi Curl package

  Curl is updated to address multiple security issues.

  e. Update to ESXi Python package

  Python is updated to address multiple security issues.

  f. vCenter and Update Manager, Oracle JRE 1.6 Update 81

  Oracle has documented the CVE identifiers that are addressed in JRE 1.6.0 update 81 in the Oracle
  Java SE Critical Patch Update Advisory of July 2014.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vCenter product updates address a Cross Site Scripting
  issue, a certificate validation issue and security vulnerabilities in third-party libraries.");

  script_tag(name:"affected", value:"VMware vCenter Server Appliance 5.1 Prior to Update 3

  VMware vCenter Server 5.5 prior to Update 2

  VMware vCenter Server 5.1 prior to Update 3

  VMware vCenter Server 5.0 prior to Update 3c");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("vmware_esx.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/server/build" ) )
  exit( 0 );

fixed_builds = make_array( "5.1.0", "2308385" );

if( ! fixed_builds[version] )
  exit( 0 );

if( int( build ) < int( fixed_builds[version ] ) ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fixed_builds[version], typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );