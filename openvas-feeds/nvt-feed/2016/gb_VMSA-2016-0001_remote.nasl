# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105509");
  script_cve_id("CVE-2015-6933");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("2023-06-28T05:05:21+0000");
  script_name("VMware ESXi updates address important guest privilege escalation vulnerability (VMSA-2016-0001) - Remote Version Check");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"A kernel memory corruption vulnerability is present in the VMware Tools 'Shared Folders' (HGFS) feature running on Microsoft Windows.
  Successful exploitation of this issue could lead to an escalation of privilege in the guest operating system.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi updates address important guest privilege escalation vulnerability");

  script_tag(name:"affected", value:"- VMware ESXi 6.0 without patch ESXi600-201512102-SG

  - VMware ESXi 5.5 without patch ESXi550-201512102-SG

  - VMware ESXi 5.1 without patch ESXi510-201510102-SG

  - VMware ESXi 5.0 without patch ESXi500-201510102-SG");

  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:22:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-14 10:45:54 +0100 (Thu, 14 Jan 2016)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.0.0", "3021432",
                           "5.1.0", "3021178",
                           "5.5.0", "3247226",
                           "6.0.0", "3341439" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message( port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );
