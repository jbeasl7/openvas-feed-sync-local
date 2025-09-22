# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106302");
  script_cve_id("CVE-2016-6420");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco FireSIGHT System Software Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-fmc1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web framework of the Cisco Firepower Management Center
running on Cisco FireSIGHT System Software could allow authenticated, remote attackers to elevate privileges
to access data outside their roles.");

  script_tag(name:"insight", value:"The vulnerability is due to improper authorization checks for authenticated
users of the system. An attacker could exploit this vulnerability by sending a crafted HTTP request to the
affected web page.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to access sensitive information
for which they are not authorized by the Firepower Management Center.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-09-29 14:36:21 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl", "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
  '4.10.3',
  '5.2.0',
  '5.3.0',
  '5.3.1',
  '5.4.0' );

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

