# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106392");
  script_cve_id("CVE-2016-6462");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco Email Security Appliance MIME Header Processing Filter Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-esa1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 9.7.2-131, 10.0.0-203 or later.");

  script_tag(name:"summary", value:"A vulnerability in the email filtering functionality of Cisco AsyncOS
Software for Cisco Email Security Appliances could allow an unauthenticated, remote attacker to bypass Advanced
Malware Protection (AMP) filters that are configured for an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to improper error handling when malformed
Multipurpose Internet Mail Extensions (MIME) headers are present in an email attachment that is sent through an
affected device. An attacker could exploit this vulnerability by sending an email message that has a crafted,
MIME-encoded file attachment through an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass AMP filter
configurations for the device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-17 11:10:15 +0700 (Thu, 17 Nov 2016)");
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
  '9.7.1-066',
  '10.0.0-125',
  '10.0.0-082' );

foreach af ( affected )
{
  if( version == af )
  {
    if (version =~ "^9")
      fix = "9.7.2-131";
    else
      fix = "10.0.0-203";

    report = report_fixed_ver(  installed_version:version, fixed_version: fix );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

