# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140078");
  script_cve_id("CVE-2016-7458", "CVE-2016-7459", "CVE-2016-7460");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_version("2024-06-28T15:38:46+0000");
  script_name("VMware vCenter Server XML External Entity (XXE) Vulnerability (VMSA-2016-0022)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0022.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted XML request issued to the server by an
  authorized user may lead to unintended information disclosure.");

  script_tag(name:"solution", value:"Update to version 6.0U2a/5.5U3e or later.");

  script_tag(name:"summary", value:"VMware vCenter Server contains an XML external entity (XXE)
  vulnerability in the Log Browser, the Distributed Switch setup, and the Content Library.");

  script_tag(name:"affected", value:"VMware vCenter Server 6.0/5.5.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-23 10:16:32 +0100 (Wed, 23 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if( version == "6.0.0" )
  if( int( build ) < int( 4541947 ) )
    fix = "6.0 U2a";

if( version == "5.5.0" )
  if( int( build ) < int( 4180646 ) )
    fix = "5.5 U3e";

if( fix ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fix, typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );