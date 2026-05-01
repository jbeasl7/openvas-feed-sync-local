# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vrealize_operations_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140064");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-11-16 15:54:11 +0100 (Wed, 16 Nov 2016)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");

  script_cve_id("CVE-2016-7457");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Operations Privilege Escalation Vulnerability (VMSA-2016-0016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_operations_manager_http_detect.nasl");
  script_mandatory_keys("vmware/vrealize/operations_manager/detected", "vmware/vrealize/operations_manager/build");

  script_tag(name:"summary", value:"VMware vRealize Operations is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploitation of this issue may allow a vROps user who has been
  assigned a low-privileged role to gain full access over the application. In addition it may be
  possible to stop and delete Virtual Machines managed by vCenter.");

  script_tag(name:"affected", value:"vRealize Operations version 6.x.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0016.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vrealize/operations_manager/build" ) )
  exit( 0 );

if( version =~ "^6\.3\.0" )
  if( int( build ) < int( 4443153 ) ) fix = '6.3.0 Build 4443153';

if( version =~ "^6\.2\.1" )
  if( int( build ) < int( 4418887 ) ) fix = '6.2.1 Build 4418887';

if( version =~ "^6\.2\.0" )
  if( int( build ) < int( 4419192 ) ) fix = '6.2.0 Build 4419192';

if( version =~ "^6\.1\.0" )
  if( int( build ) < int( 4422776 ) ) fix = '6.1.0 Build 4422776';

if( fix ) {
  report = report_fixed_ver( installed_version:version + ' Build ' + build, fixed_version:fix );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );
