# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105606");
  script_cve_id("CVE-2016-2076");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2026-04-28T06:28:06+0000");
  script_name("VMware Security Updates for vCenter Server (VMSA-2016-0004)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0004.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"- Critical VMware Client Integration Plugin incorrect session
  handling:

  The VMware Client Integration Plugin does not handle session content in a safe way. This may allow
  for a Man in the Middle attack or Web session hijacking in case the user of the vSphere Web Client
  visits a malicious Web site.");

  script_tag(name:"solution", value:"Update to 6.0U2/5.5U3d. In order to remediate the issue, both
  the server side and the client side (i.e. CIP of the vSphere Web Client) will need to be updated.");

  script_tag(name:"summary", value:"VMware vCenter Server updates address a critical security issue.");

  script_tag(name:"affected", value:"VMware vCenter Server 6.0 prior to 6.0 U2 and VMware vCenter
  Server 5.5 U3a, U3b, U3c");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-04-15 18:13:05 +0200 (Fri, 15 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_vmware_vcenter_server_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/server/detected", "vmware/vcenter/server/build");

  exit(0);
}

include("host_details.inc");
include("vmware_esx.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/server/build" ) )
  exit( 0 );

if( version == "6.0.0" )
  if( int( build ) < int( 3634788 ) ) fix = "3634788 (6.0U2)";

if( version == "5.5.0" )
  # Affected 5.5 U3a-U3c. 5.5 U3a Build is 3154313. 5.5 U3d Build is 3730491.
  if( version_in_range( version:build, test_version:"3142196", test_version2:"3730490" ) ) fix = "3730491 (5.5U3d)";

if( fix ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fix, typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );