# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105801");
  script_cve_id("CVE-2016-1442");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Prime Infrastructure Administrative Web Interface HTML Injection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160706-pi");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by inserting crafting input into the affected fields of the web interface.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to improper user input validation.");
  script_tag(name:"solution", value:"To address this vulnerability, Cisco plans to release a software update in the third quarter of 2016. The expected fixed software version will be 3.1.1.");
  script_tag(name:"summary", value:"A vulnerability in the administrative web interface of Cisco Prime Infrastructure (PI) could allow an authenticated, remote attacker to execute arbitrary commands on the affected system and on the devices managed by the system.");
  script_tag(name:"affected", value:"Cisco Prime Infrastructure versions 3.1.0 and prior are affected.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-29 17:46:00 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-07-07 13:42:52 +0200 (Thu, 07 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_pis_version.nasl");
  script_mandatory_keys("cisco_pis/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^3\." )
  if( version_is_less( version:version, test_version:'3.1.1' ) ) fix = '3.1.1';

if( fix )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

