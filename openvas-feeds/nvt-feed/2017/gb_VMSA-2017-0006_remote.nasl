# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140231");
  script_cve_id("CVE-2017-4902", "CVE-2017-4903", "CVE-2017-4904", "CVE-2017-4905");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-06-28T05:05:21+0000");

  script_name("VMware ESXi updates address critical and moderate security issues (VMSA-2017-0006) - Remote Version Check");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0006.html");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi updates address critical and moderate
security issues.");

  script_tag(name:"insight", value:"ESXi has a heap buffer overflow and uninitialized stack memory usage in SVGA. These issues may allow a guest to execute code on the host.");

  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-03 19:03:00 +0000 (Thu, 03 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-03-31 10:54:50 +0200 (Fri, 31 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "6.0.0", "5224934",
                           "6.5.0", "5224529" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message( port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );
