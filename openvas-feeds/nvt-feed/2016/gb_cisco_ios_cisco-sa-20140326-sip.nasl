# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105652");
  script_cve_id("CVE-2014-2106");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-sip");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20140326-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=33344");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAMBAlert.x?alertId=32537");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_mar14.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP) implementation in
  Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload
  of an affected device. To exploit this vulnerability, affected devices must be configured to process SIP messages.
  Limited Cisco IOS Software and Cisco IOS XE Software releases are affected.

  Cisco has released software updates that address this vulnerability.

  There are no workarounds for devices that must run SIP. However, mitigations are available to limit exposure to this vulnerability.

  Note: The March 26, 2014, Cisco IOS Software Security Advisory bundled publication includes six Cisco Security Advisories.
  All advisories address vulnerabilities in Cisco IOS Software. Each Cisco IOS Software Security Advisory lists the Cisco IOS
  Software releases that correct the vulnerability or vulnerabilities detailed in the advisory as well as the Cisco IOS Software
  releases that correct all Cisco IOS Software vulnerabilities in the March 2014 bundled publication.

  Individual publication links are in Cisco Event Response: Semiannual Cisco IOS Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-04 18:52:15 +0200 (Wed, 04 May 2016)");
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
  '15.3(3)M1' );

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

