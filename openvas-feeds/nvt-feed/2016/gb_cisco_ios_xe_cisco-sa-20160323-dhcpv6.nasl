# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105664");
  script_cve_id("CVE-2016-1348");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS and IOS XE Software DHCPv6 Relay Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20160323-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the DHCP version 6 (DHCPv6) relay feature of Cisco IOS
  and IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload.

  The vulnerability is due to insufficient validation of DHCPv6 relay messages. An attacker could exploit
  this vulnerability by sending a crafted DHCPv6 relay message to an affected device. A successful exploit
  could allow the attacker to cause the affected device to reload, resulting in a denial of service (DoS) condition.

  Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication,
  which includes six Cisco Security Advisories that describe six vulnerabilities. All the vulnerabilities have a
  Security Impact Rating of `High.` For a complete list of advisories and links to them, see Cisco Event Response:
  Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:20:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-09 17:36:49 +0200 (Mon, 09 May 2016)");
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
  '3.8.0E',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.6.0E',
  '3.6.1E',
  '3.6.2a.E',
  '3.6.2E',
  '3.6.3E',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.2t.S',
  '3.7.3S',
  '3.7.4S',
  '3.7.4a.S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.0a.S',
  '3.9.1S',
  '3.9.1a.S',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xb.S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.4S',
  '3.12.2S',
  '3.12.3S',
  '3.13.2a.S',
  '3.13.0S',
  '3.13.0a.S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.1c.S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S' );

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
