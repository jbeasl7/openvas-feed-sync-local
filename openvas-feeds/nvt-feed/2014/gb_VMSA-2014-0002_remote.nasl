# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103916");
  script_cve_id("CVE-2013-5211", "CVE-2013-4332");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-06-28T05:05:21+0000");
  script_name("VMware ESXi updates to third party libraries (VMSA-2014-0002) - Remote Version Check");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-03-12 14:04:01 +0100 (Wed, 12 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0002.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. DDoS vulnerability in NTP third party libraries

  The NTP daemon has a DDoS vulnerability in the handling of the
  'monlist' command. An attacker may send a forged request to a
  vulnerable NTP server resulting in an amplified response to the
  intended target of the DDoS attack.

  b. Update to ESXi glibc package

  The ESXi glibc package is updated to version glibc-2.5-118.el5_10.2 to
  resolve a security issue.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware has updated ESXi third party libraries.");

  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201403101-SG.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.5.0", "1623387" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) ) {
  security_message(port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );
