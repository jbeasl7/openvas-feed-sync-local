# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106526");
  script_cve_id("CVE-2017-3800");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Email Security Appliance Filter Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-esa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the content scanning engine of Cisco AsyncOS Software
for Cisco Email Security Appliances (ESA) could allow an unauthenticated, remote attacker to bypass configured
message or content filters on the device.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation of email message
attachments in different formats. An attacker could exploit this vulnerability by sending a crafted email message
with an attachment to the ESA.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to bypass configured content or message
filters configured on the ESA. This message filter bypass could allow email attachments that contain malware to
pass through the targeted device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-26 01:29:00 +0000 (Wed, 26 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-01-19 10:40:17 +0700 (Thu, 19 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
                '9.7.1-066',
                '9.7.1-HP2-207',
                '9.8.5-085' );

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

