# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105630");
  script_cve_id("CVE-2016-1350");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IOS and IOS XE and Cisco Unified Communications Manager Software Session Initiation Protocol Memory Leak Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP) gateway
  implementation in Cisco IOS, IOS XE, and Cisco Unified Communications Manager Software could allow
  an unauthenticated, remote attacker to cause a memory leak and eventual reload of an affected device.

  The vulnerability is due to improper processing of malformed SIP messages. An attacker could exploit
  this vulnerability by sending malformed SIP messages to be processed by an affected device.
  An exploit could allow the attacker to cause a memory leak and eventual reload of the affected device.

  Cisco has released software updates that address this vulnerability. There are no workarounds that
  address this vulnerability other than disabling SIP on the vulnerable device.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory
  Bundled Publication, which includes six Cisco Security Advisories that describe six vulnerabilities.
  All the vulnerabilities have a Security Impact Rating of `High.` For a complete list of advisories and links to them,
  see Cisco Event Response: Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-12 01:29:00 +0000 (Fri, 12 May 2017)");
  script_tag(name:"creation_date", value:"2016-05-03 17:28:55 +0200 (Tue, 03 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(3)M2',
  '15.3(1)S1',
  '15.3(1)S2',
  '15.3(2)S0a',
  '15.3(2)S2',
  '15.3(1)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(1)T4',
  '15.3(2)T',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.3(2)T4',
  '15.4(1)CG',
  '15.4(2)CG',
  '15.4(1)T',
  '15.4(1)T1',
  '15.4(2)T' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

