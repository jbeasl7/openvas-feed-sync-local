# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105678");
  script_cve_id("CVE-2015-1791", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1792", "CVE-2014-8176");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2025-03-07T15:40:19+0000");

  script_name("Multiple Vulnerabilities in OpenSSL (June 2015) Affecting Cisco Products (cisco-sa-20150612-openssl)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150612-openssl");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"On June 11, 2015, the OpenSSL Project released a security advisory detailing six distinct
  vulnerabilities, and another fix that provides hardening protections against exploits as described in the Logjam research.

  Multiple Cisco products incorporate a version of the OpenSSL package affected by one or more vulnerabilities that could allow
  an unauthenticated, remote attacker to cause a denial of service (DoS) condition or corrupt portions of OpenSSL process memory.

  Cisco will release software updates that address these vulnerabilities.

  Workarounds that mitigate these vulnerabilities may be available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-05-10 10:53:28 +0200 (Tue, 10 May 2016)");
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
  '3.3.0S',
  '3.3.1S',
  '3.3.2S',
  '3.4.0S',
  '3.4.1S',
  '3.4.2S',
  '3.4.3S',
  '3.4.4S',
  '3.4.5S',
  '3.4.6S',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S' );

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
