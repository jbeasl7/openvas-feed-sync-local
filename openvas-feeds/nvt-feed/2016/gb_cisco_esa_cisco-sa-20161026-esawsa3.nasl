# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140021");
  script_cve_id("CVE-2016-6360");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2025-01-21T05:37:33+0000");

  script_name("Cisco Email Security Appliance JAR Advanced Malware Protection DoS Vulnerability (cisco-sa-20161026-esawsa3)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-esawsa3");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in Advanced Malware Protection (AMP) for Cisco Email Security Appliances (ESA) and
  Web Security Appliances (WSA) could allow an unauthenticated, remote attacker to cause a partial
  denial of service (DoS) condition due to the AMP process unexpectedly restarting.

  The vulnerability is due to improper validation of a Java Archive (JAR) file scanned when AMP is
  configured. An attacker could exploit this vulnerability by crafting a JAR file, and attaching
  this JAR file to an email that is then sent through the affected device. An exploit could allow
  the attacker to cause the Cisco ESA and WSA AMP process to unexpectedly restart due to the
  malformed JAR file.

  Cisco has released software updates that address this vulnerability. Workarounds that address this
  vulnerability are not available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-10-27 13:46:30 +0200 (Thu, 27 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '9.5.0-000',
  '9.5.0-201',
  '9.6.0-000',
  '9.6.0-042',
  '9.6.0-051',
  '9.7.0-125' );

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
