# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105088");
  script_cve_id("CVE-2014-0114", "CVE-2013-4590", "CVE-2013-4322", "CVE-2014-0050", "CVE-2013-0242", "CVE-2013-1914");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2026-04-28T06:28:06+0000");
  script_name("VMware Security Updates for vCenter Server (VMSA-2014-0008)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. vCenter Server Apache Struts Update

  The Apache Struts library is updated to address a security issue. This issue may lead to remote
  code execution after authentication.

  b. vCenter Server tc-server 2.9.5 / Apache Tomcat 7.0.52 updates

  tc-server has been updated to version 2.9.5 to address multiple security issues. This version of
  tc-server includes Apache Tomcat 7.0.52.

  c. Update to ESXi glibc package

  glibc is updated to address multiple security issues.

  d. vCenter and Update Manager, Oracle JRE 1.7 Update 55

  Oracle has documented the CVE identifiers that are addressed in JRE 1.7.0 update 55 in the Oracle
  Java SE Critical Patch Update Advisory of April 2014");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"VMware has updated vSphere third party libraries.");

  script_tag(name:"affected", value:"VMware vCenter Server 5.5 prior to Update 2.");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2014-09-11 11:04:02 +0100 (Thu, 11 Sep 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_vcenter_server_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/server/detected", "vmware/vcenter/server/build");

  exit(0);
}

include("host_details.inc");
include("vmware_esx.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/server/build" ) )
  exit( 0 );

fixed_builds = make_array( "5.5.0", "2001466" );

if( ! fixed_builds[version] )
  exit( 0 );

if( int( build ) < int( fixed_builds[version ] ) ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fixed_builds[version], typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );