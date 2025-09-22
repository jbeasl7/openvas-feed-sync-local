# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105134");
  script_cve_id("CVE-2014-3797", "CVE-2014-8371", "CVE-2013-2877", "CVE-2014-0191", "CVE-2014-0015",
                "CVE-2014-0138", "CVE-2013-1752", "CVE-2013-4238");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("2023-06-28T05:05:21+0000");
  script_name("VMware ESXi updates address security vulnerabilities (VMSA-2014-0012) - Remote Version Check");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-12-05 11:32:51 +0100 (Fri, 05 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. Update to ESXi libxml2 package
  libxml2 is updated to address multiple security issues.

  b. Update to ESXi Curl package
  Curl is updated to address multiple security issues.

  c. Update to ESXi Python package
  Python is updated to address multiple security issues.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi updates address a Cross Site Scripting issue, a certificate validation
  issue and security vulnerabilities in third-party libraries.");

  script_tag(name:"affected", value:"VMware ESXi 5.1 without patch ESXi510-201412101-SG.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.1.0", "2323231" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) ) {
  security_message( port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit( 0 );
}

exit( 99 );
