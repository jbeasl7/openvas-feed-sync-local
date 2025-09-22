# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106158");
  script_cve_id("CVE-2016-1461");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Email Security Appliance File Type Filtering Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160727-esa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Cisco ESA version 9.1.1-038 or
 later.");

  script_tag(name:"summary", value:"A vulnerability in the email message filtering feature of Cisco AsyncOS
for Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to cause an ESA to
fail to detect and act upon a specific type of file that is attached to an email message.

The vulnerability is due to improper application of message filtering rules to email attachments that contain
a specific type of file and are submitted to an affected appliance. An attacker could exploit this vulnerability
by sending an email message with a crafted attachment to an affected appliance. A successful exploit could allow
the attacker to cause the ESA to fail to detect and act upon possible malware in the email attachment.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-01 18:11:00 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-07-29 11:42:15 +0700 (Fri, 29 Jul 2016)");
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
  '7.1.0',
  '7.1.1',
  '7.1.2',
  '7.1.3',
  '7.1.4',
  '7.1.5',
  '7.3.0',
  '7.3.1',
  '7.3.2',
  '7.5.0',
  '7.5.1',
  '7.5.2',
  '7.5.2-201',
  '7.6.0',
  '7.6.1-000',
  '7.6.1-gpl-022',
  '7.6.2',
  '7.6.3-000',
  '7.6.3-025',
  '7.7.0-000',
  '7.7.1-000',
  '7.8.0',
  '7.8.0-311',
  '8.0 Base',
  '8.0.1-023',
  '8.5.0-000',
  '8.5.0-ER1-198',
  '8.5.6-052',
  '8.5.6-073',
  '8.5.6-074',
  '8.5.6-106',
  '8.5.6-113',
  '8.5.7-042',
  '8.6.0',
  '8.6.0-011',
  '8.9.0',
  '8.9.1-000',
  '8.9.2-032',
  '9.0.0',
  '9.0.0-212',
  '9.0.0-461',
  '9.0.5-000',
  '9.1.0',
  '9.1.0-011',
  '9.1.0-101',
  '9.1.0-032',
  '9.1.1-000',
  '9.4.0',
  '9.4.4-000',
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
    report = report_fixed_ver(  installed_version:version, fixed_version: "9.1.1-038" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

