# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105668");
  script_cve_id("CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852",
                "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7871", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7703",
                "CVE-2015-7701", "CVE-2015-7855", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7702");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-02-19T14:37:31+0000");

  script_name("Multiple Vulnerabilities in ntpd Affecting Cisco Products (Oct 2015)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-ntp");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=41653");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=41658");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"Multiple Cisco products incorporate a version of the ntpd package.
  Versions of this package are affected by one or more vulnerabilities that could allow an unauthenticated,
  remote attacker to create a denial of service (DoS) condition or modify the time being advertised by a
  device acting as a network time protocol (NTP) server.

  On October 21st, 2015, NTP.org released a security advisory detailing 13 issues regarding multiple DoS
  vulnerabilities, information disclosure vulnerabilities, and logic issues that may result in an attacker
  gaining the ability to modify an NTP server's advertised time. The vulnerabilities covered in this document are as follows:

  - CVE-2015-7691 - Denial of Service AutoKey Malicious Message

  - CVE-2015-7692 - Denial of Service AutoKey Malicious Message

  - CVE-2015-7701 - Denial of Service CRYPTO_ASSOC Memory Leak

  - CVE-2015-7702 - Denial of Service AutoKey Malicious Message

  - CVE-2015-7703 - Configuration Directive File Overwrite Vulnerability

  - CVE-2015-7704 - Denial of Service by Spoofed Kiss-o'-Death

  - CVE-2015-7705 - Denial of Service by Priming the Pump

  - CVE-2015-7848 - Network Time Protocol ntpd Multiple Integer Overflow Read Access Violations

  - CVE-2015-7849 - Network Time Protocol Trusted Keys Memory Corruption Vulnerability

  - CVE-2015-7850 - Network Time Protocol Remote Configuration Denial of Service Vulnerability

  - CVE-2015-7851 - Network Time Protocol ntpd saveconfig Directory Traversal Vulnerability

  - CVE-2015-7852 - Network Time Protocol ntpq atoascii Memory Corruption Vulnerability

  - CVE-2015-7853 - Network Time Protocol Reference Clock Memory Corruption Vulnerability

  - CVE-2015-7854 - Network Time Protocol Password Length Memory Corruption Vulnerability

  - CVE-2015-7855 - Denial of Service Long Control Packet Message

  - CVE-2015-7871 - NAK to the Future: NTP Symmetric Association Authentication Bypass Vulnerability

  Cisco will release software updates that address these vulnerabilities.

  Workarounds that mitigate one or more of the vulnerabilities may be available for certain products, please see the individual Cisco Bug IDs for details.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-05-09 18:22:34 +0200 (Mon, 09 May 2016)");
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
  '2.1.0',
  '2.1.1',
  '2.1.2',
  '2.2.1',
  '2.2.2',
  '2.2.3',
  '2.3.0',
  '2.3.0t',
  '2.3.1t',
  '2.3.2',
  '2.4.0',
  '2.4.1',
  '2.5.0',
  '2.5.1',
  '2.5.2',
  '2.6.0',
  '2.6.1',
  '2.6.2',
  '3.1.0S',
  '3.1.1S',
  '3.1.2S',
  '3.1.3S',
  '3.1.4S',
  '3.1.5S',
  '3.1.6S',
  '3.1.0SG',
  '3.1.1SG',
  '3.2.0S',
  '3.2.1S',
  '3.2.2S',
  '3.2.3S',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.0XO',
  '3.2.1XO',
  '3.3.0S',
  '3.3.1S',
  '3.3.2S',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0SG',
  '3.3.1SG',
  '3.3.2SG',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0S',
  '3.4.1S',
  '3.4.2S',
  '3.4.3S',
  '3.4.4S',
  '3.4.5S',
  '3.4.6S',
  '3.4.0SG',
  '3.4.1SG',
  '3.4.2SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.6.0E',
  '3.6.1E',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.0E',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
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
  '3.10.5S',
  '3.10.6S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S' );

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
