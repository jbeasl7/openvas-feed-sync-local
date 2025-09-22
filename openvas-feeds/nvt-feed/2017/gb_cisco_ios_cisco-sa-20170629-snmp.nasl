# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106914");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-6744", "CVE-2017-6743", "CVE-2017-6742", "CVE-2017-6741", "CVE-2017-6740", "CVE-2017-6739",
"CVE-2017-6738", "CVE-2017-6737", "CVE-2017-6736");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2024-07-17T05:05:38+0000");

  script_name("SNMP Remote Code Execution Vulnerabilities in Cisco IOS Software");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The Simple Network Management Protocol (SNMP) subsystem of Cisco IOS Software
contains multiple vulnerabilities that could allow an authenticated, remote attacker to remotely execute code on
an affected system or cause an affected system to reload. An attacker could exploit these vulnerabilities by
sending a crafted SNMP packet to an affected system via IPv4 or IPv6. Only traffic directed to an affected system
can be used to exploit these vulnerabilities.");

  script_tag(name:"insight", value:"The vulnerabilities are due to a buffer overflow condition in the SNMP
subsystem of the affected software. The vulnerabilities affect all versions of SNMP - Versions 1, 2c, and 3. To
exploit these vulnerabilities via SNMP Version 2c or earlier, the attacker must know the SNMP read-only community
string for the affected system. To exploit these vulnerabilities via SNMP Version 3, the attacker must have user
credentials for the affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary code and
obtain full control of the affected system or cause the affected system to reload.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:32:07 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-06-30 14:53:03 +0700 (Fri, 30 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
                '12.4(24)T4',
                '15.1(4)M',
                '15.5(3)S',
                '15.6(1)T0.1',
                '15.6(3)M1',
                '16.5(1)' );

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

