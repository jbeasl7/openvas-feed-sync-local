# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105670");
  script_cve_id("CVE-2015-0646");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS Software and IOS XE Software TCP Packet Memory Leak Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-tcpleak");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAMBAlert.x?alertId=37433");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37821");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=43609");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150325-bundle");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_mar15.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the TCP input module of Cisco IOS and Cisco IOS XE
  Software could allow an unauthenticated, remote attacker to cause a memory leak and eventual reload of the affected device.

  The vulnerability is due to improper handling of certain crafted packet sequences used in establishing a TCP three-way handshake.
  An attacker could exploit this vulnerability by sending a crafted sequence of TCP packets while establishing a three-way handshake.
  A successful exploit could allow the attacker to cause a memory leak and eventual reload of the affected device.

  There are no workarounds for this vulnerability.

  Cisco has released software updates that address this vulnerability. This advisory is available at the references.

  Note: The March 25, 2015, Cisco IOS & XE Software Security Advisory bundled publication includes seven Cisco Security Advisories.
  The advisories address vulnerabilities in Cisco IOS Software and Cisco IOS XE Software. Individual publication links are in Cisco Event
  Response: Semiannual Cisco IOS & XE Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-09 18:27:39 +0200 (Mon, 09 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list(
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S',
  '3.10.0S',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
