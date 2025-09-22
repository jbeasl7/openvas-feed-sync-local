# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140032");
  script_cve_id("CVE-2016-1480");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Web Security Appliance Malformed MIME Header Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-esawsa1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Multipurpose Internet Mail Extensions (MIME) scanner of Cisco AsyncOS
Software for Cisco Email Security Appliances (ESA) and Web Security Appliances (WSA) could allow an
unauthenticated, remote attacker to bypass configured user filters on the device.

The vulnerability is due to improper error handling of a malformed MIME header in an email
attachment. An attacker could exploit this vulnerability by sending an email with a crafted MIME
attachment. For example, a successful exploit could allow the attacker to bypass configured user
filters to prevent executable files from being opened. The malformed MIME headers may not be RFC
compliant but some mail clients could still allow users to access the attachment, which may not have
been properly filtered by the device.

Cisco has released software updates that address this vulnerability. Workarounds that address this
vulnerability are not available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-10-27 14:57:45 +0200 (Thu, 27 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '8.0.0',
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

